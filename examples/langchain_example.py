#!/usr/bin/env python3
"""
LangChain example: a LangChain agent that verifies its Cord Protocol
identity before executing any tool.

LangChain imports are stubbed with comments so this file runs without
LangChain installed.  In a real project uncomment the imports and remove
the stub classes below.

Run with:
    python examples/langchain_example.py
"""

# ── LangChain imports (uncomment in a real project) ──────────────────────────
# from langchain.agents import AgentExecutor, create_openai_tools_agent
# from langchain.tools import BaseTool
# from langchain_openai import ChatOpenAI
# from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
# from pydantic import Field as PydanticField
# ─────────────────────────────────────────────────────────────────────────────

# ── Stubs so this example runs standalone ────────────────────────────────────
class BaseTool:  # noqa: D101
    name: str = ""
    description: str = ""

    def _run(self, *args, **kwargs): ...  # noqa: D102

    def run(self, tool_input: str) -> str:  # noqa: D102
        return self._run(tool_input)
# ─────────────────────────────────────────────────────────────────────────────

from cordprotocol import (
    SCOPES,
    AgentCredential,
    generate_keypair,
    has_permission,
    issue_credential,
    verify_credential,
)

# ---------------------------------------------------------------------------
# Issuer setup
# In production: generate once, persist securely (e.g. in a KMS or vault).
# ---------------------------------------------------------------------------
_ISSUER_KEYPAIR = generate_keypair()


def issue_agent_credential(agent_id: str) -> AgentCredential:
    """Issue a short-lived credential for a LangChain agent instance."""
    return issue_credential(
        agent_id=agent_id,
        issued_to="langchain-runtime",
        permissions=[SCOPES.READ, SCOPES.EXECUTE, SCOPES.COMMUNICATE],
        expires_in="1h",
        private_key=_ISSUER_KEYPAIR.private_key,
    )


# ---------------------------------------------------------------------------
# A tool that requires a valid Cord credential before it will run
# ---------------------------------------------------------------------------

class CordProtectedDatabaseTool(BaseTool):
    """LangChain tool: query the production database.

    Cord Protocol is used to verify the calling agent's identity and
    check the required permission scope before any real work happens.
    """

    name = "database_query"
    description = "Query the production database. Requires read:data permission."

    def __init__(self, credential: AgentCredential) -> None:
        super().__init__()
        self.credential = credential

    def _run(self, query: str) -> str:
        # Step 1 — verify the credential is still valid
        result = verify_credential(self.credential)
        if not result.valid:
            raise PermissionError(
                f"Agent identity verification failed: {result.error}"
            )

        # Step 2 — enforce the scope required by this specific tool
        if not has_permission(self.credential, SCOPES.READ):
            raise PermissionError(
                f"Agent '{self.credential.agent_id}' lacks '{SCOPES.READ}' permission."
            )

        # Step 3 — execute the tool
        print(f"  [CordProtectedTool] agent={self.credential.agent_id}")
        print(f"  [CordProtectedTool] query={query!r}")
        return f"Simulated result for query: {query}"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_demo() -> None:
    agent_id = "langchain-prod-agent-001"

    # Issue a credential for this agent session
    credential = issue_agent_credential(agent_id)
    print(f"Credential issued for agent: {agent_id}")
    print(f"  Permissions : {credential.permissions}")
    print(f"  Expires at  : {credential.expires_at}")
    print()

    # Attach it to a Cord-protected tool
    tool = CordProtectedDatabaseTool(credential=credential)

    # In a real LangChain project you would wire this up as:
    #
    #   llm = ChatOpenAI(model="gpt-4o")
    #   tools = [tool]
    #   prompt = ChatPromptTemplate.from_messages([
    #       ("system", "You are a helpful assistant."),
    #       MessagesPlaceholder("chat_history", optional=True),
    #       ("human", "{input}"),
    #       MessagesPlaceholder("agent_scratchpad"),
    #   ])
    #   agent = create_openai_tools_agent(llm, tools, prompt)
    #   executor = AgentExecutor(agent=agent, tools=tools)
    #   result = executor.invoke({"input": "List the 10 most recent users"})
    #
    # For this standalone demo we call the tool directly:
    print("Calling CordProtectedDatabaseTool...")
    result = tool.run("SELECT * FROM users ORDER BY created_at DESC LIMIT 10")
    print(f"  Result: {result}")
    print()

    # Demonstrate that a missing permission blocks the tool
    print("Testing a credential without read:data permission...")
    restricted_cred = issue_credential(
        agent_id="read-only-agent",
        issued_to="langchain-runtime",
        permissions=[SCOPES.EXECUTE],  # no read:data
        expires_in="1h",
        private_key=_ISSUER_KEYPAIR.private_key,
    )
    restricted_tool = CordProtectedDatabaseTool(credential=restricted_cred)
    try:
        restricted_tool.run("SELECT * FROM secrets")
    except PermissionError as exc:
        print(f"  Blocked as expected: {exc}")


if __name__ == "__main__":
    run_demo()
