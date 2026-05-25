#!/usr/bin/env python3
"""
CrewAI example: establish trust between agents in a crew using
Cord Protocol credentials.

CrewAI imports are stubbed with comments so this file runs without
CrewAI installed.  In a real project uncomment the imports and remove
the stub classes below.

Run with:
    python examples/crewai_example.py
"""

# ── CrewAI imports (uncomment in a real project) ─────────────────────────────
# from crewai import Agent, Crew, Process, Task
# from crewai.tools import BaseTool
# ─────────────────────────────────────────────────────────────────────────────

# ── Stubs so this example runs standalone ────────────────────────────────────
class Agent:  # noqa: D101
    def __init__(self, role, goal, backstory, tools=None, **_):
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.tools = tools or []

    def __repr__(self):
        return f"Agent(role={self.role!r})"


class Task:  # noqa: D101
    def __init__(self, description, agent, expected_output="", **_):
        self.description = description
        self.agent = agent
        self.expected_output = expected_output


class Crew:  # noqa: D101
    def __init__(self, agents, tasks, **_):
        self.agents = agents
        self.tasks = tasks

    def kickoff(self) -> str:
        print(f"[Crew] Starting with {len(self.agents)} agent(s) "
              f"and {len(self.tasks)} task(s)")
        for task in self.tasks:
            print(f"  Task: {task.description[:70]}...")
        return "Crew completed (simulated)"


class BaseTool:  # noqa: D101
    name: str = ""
    description: str = ""

    def _run(self, *args, **kwargs): ...  # noqa: D102
# ─────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass
from typing import Dict, List, Optional

from cordprotocol import (
    SCOPES,
    AgentCredential,
    KeyPair,
    generate_keypair,
    has_permission,
    issue_credential,
    verify_credential,
)


# ---------------------------------------------------------------------------
# Trust registry — issues and verifies Cord credentials for a crew session
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """Pairs an agent's keypair with its issued credential."""

    agent_id: str
    keypair: KeyPair
    credential: AgentCredential


class CordTrustRegistry:
    """In-memory trust registry for a CrewAI crew session.

    In production this could be backed by a database, distributed ledger,
    or secrets manager.  The registry acts as the issuing authority: it
    holds one root keypair and issues short-lived credentials to every
    agent that joins the crew.
    """

    def __init__(self) -> None:
        self._issuer_keypair: KeyPair = generate_keypair()
        self._registry: Dict[str, AgentIdentity] = {}

    @property
    def issuer_public_key(self) -> str:
        return self._issuer_keypair.public_key

    def register_agent(
        self,
        agent_id: str,
        permissions: List[str],
        expires_in: str = "2h",
    ) -> AgentIdentity:
        """Register an agent and issue it a credential."""
        keypair = generate_keypair()
        credential = issue_credential(
            agent_id=agent_id,
            issued_to="crewai-runtime",
            permissions=permissions,
            expires_in=expires_in,
            private_key=self._issuer_keypair.private_key,
        )
        identity = AgentIdentity(
            agent_id=agent_id,
            keypair=keypair,
            credential=credential,
        )
        self._registry[agent_id] = identity
        return identity

    def verify_agent(self, agent_id: str) -> bool:
        """Return True if the agent has a valid, non-expired credential."""
        identity = self._registry.get(agent_id)
        if identity is None:
            return False
        return verify_credential(identity.credential).valid

    def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._registry.get(agent_id)


# ---------------------------------------------------------------------------
# A tool that lets one agent verify another agent's Cord identity
# ---------------------------------------------------------------------------

class TrustVerifyTool(BaseTool):
    """Tool: verify that a peer agent has a valid Cord credential.

    The calling agent's own identity is checked first, then the target's.
    This creates a chain of trust: only verified agents can vouch for others.
    """

    name = "verify_peer_agent"
    description = "Verify that another agent in this crew has a valid Cord identity."

    def __init__(self, registry: CordTrustRegistry, caller_id: str) -> None:
        super().__init__()
        self.registry = registry
        self.caller_id = caller_id

    def _run(self, target_agent_id: str) -> str:
        # The caller must also be verified
        if not self.registry.verify_agent(self.caller_id):
            return (
                f"ERROR: Caller '{self.caller_id}' has no valid credential. "
                "Cannot vouch for other agents."
            )

        if self.registry.verify_agent(target_agent_id):
            identity = self.registry.get_identity(target_agent_id)
            return (
                f"TRUSTED: '{target_agent_id}' has a valid credential. "
                f"Permissions: {identity.credential.permissions}"
            )

        return f"UNTRUSTED: '{target_agent_id}' could not be verified."


# ---------------------------------------------------------------------------
# Demo: build and run a trusted crew
# ---------------------------------------------------------------------------

def build_trusted_crew() -> None:
    print("=" * 60)
    print("CordProtocol + CrewAI Trust Demo")
    print("=" * 60)
    print()

    # 1. Create the crew's trust registry
    registry = CordTrustRegistry()
    print(f"Trust registry created (issuer key: {registry.issuer_public_key[:24]}...)")
    print()

    # 2. Register agents with appropriate permission scopes
    researcher = registry.register_agent(
        "researcher-agent",
        permissions=[SCOPES.READ, SCOPES.COMMUNICATE],
    )
    writer = registry.register_agent(
        "writer-agent",
        permissions=[SCOPES.READ, SCOPES.WRITE, SCOPES.COMMUNICATE],
    )
    reviewer = registry.register_agent(
        "reviewer-agent",
        permissions=[SCOPES.READ, SCOPES.EXECUTE, SCOPES.COMMUNICATE],
    )

    print("Registered agents:")
    for identity in [researcher, writer, reviewer]:
        cred = identity.credential
        print(f"  {cred.agent_id:<20} permissions={cred.permissions}")
    print()

    # 3. Demonstrate inter-agent trust verification
    researcher_tool = TrustVerifyTool(registry, "researcher-agent")
    writer_tool = TrustVerifyTool(registry, "writer-agent")

    print("Researcher verifying writer's identity:")
    print(f"  {researcher_tool._run('writer-agent')}")
    print()

    print("Writer verifying reviewer's identity:")
    print(f"  {writer_tool._run('reviewer-agent')}")
    print()

    print("Researcher trying to verify an unknown agent:")
    print(f"  {researcher_tool._run('unknown-agent-99')}")
    print()

    # 4. Check that scopes are enforced as expected
    print("Permission checks:")
    print(f"  researcher can WRITE? "
          f"{has_permission(researcher.credential, SCOPES.WRITE)}")
    print(f"  writer can WRITE?     "
          f"{has_permission(writer.credential, SCOPES.WRITE)}")
    print(f"  reviewer can EXECUTE? "
          f"{has_permission(reviewer.credential, SCOPES.EXECUTE)}")
    print()

    # 5. Build the CrewAI agents with credential context
    researcher_agent = Agent(
        role="Senior Research Analyst",
        goal="Research post-quantum cryptography advances with a verified identity",
        backstory=(
            f"You are agent '{researcher.agent_id}' with a valid Cord Protocol "
            f"credential (ID: {researcher.credential.id[:8]}...). "
            "You have read and communicate permissions."
        ),
        tools=[researcher_tool],
    )
    writer_agent = Agent(
        role="Technical Content Writer",
        goal="Write clear documentation about PQ crypto for AI agent developers",
        backstory=(
            f"You are agent '{writer.agent_id}' with a valid Cord Protocol "
            f"credential (ID: {writer.credential.id[:8]}...). "
            "You have read, write, and communicate permissions."
        ),
        tools=[writer_tool],
    )

    # 6. Define tasks
    tasks = [
        Task(
            description=(
                "Research the latest NIST post-quantum cryptography standards "
                "and how they apply to AI agent identity systems."
            ),
            agent=researcher_agent,
            expected_output="A summary of PQ crypto standards relevant to AI agents",
        ),
        Task(
            description=(
                "Write a developer guide explaining how to use Cord Protocol "
                "credentials in a LangChain or CrewAI project."
            ),
            agent=writer_agent,
            expected_output="A polished developer guide in Markdown format",
        ),
    ]

    # 7. Assemble and kick off the crew
    crew = Crew(agents=[researcher_agent, writer_agent], tasks=tasks)
    result = crew.kickoff()
    print()
    print(f"Crew result: {result}")
    print()
    print("All agents operated with verified Cord Protocol identities.")


if __name__ == "__main__":
    build_trusted_crew()
