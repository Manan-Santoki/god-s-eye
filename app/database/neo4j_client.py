"""
Async Neo4j client for graph database operations.

All Cypher queries use parameterized queries — never string interpolation.
All operations are async using the neo4j[async] driver.

Usage:
    client = Neo4jClient()
    await client.connect()
    person_id = await client.create_person("John Doe", {"age": 30})
    email_id = await client.create_email("john@example.com")
    await client.link_nodes(person_id, email_id, "HAS_EMAIL")
    await client.disconnect()
"""

from typing import Any
from uuid import uuid4

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession

from app.core.config import settings
from app.core.exceptions import DatabaseError
from app.core.logging import get_logger

logger = get_logger(__name__)

# All indexes to create on startup
INDEXES = [
    "CREATE INDEX person_name IF NOT EXISTS FOR (p:Person) ON (p.name)",
    "CREATE INDEX email_address IF NOT EXISTS FOR (e:Email) ON (e.address)",
    "CREATE INDEX username_handle IF NOT EXISTS FOR (u:Username) ON (u.handle)",
    "CREATE INDEX username_platform IF NOT EXISTS FOR (u:Username) ON (u.platform)",
    "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
    "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
    "CREATE INDEX image_hash IF NOT EXISTS FOR (img:Image) ON (img.hash_md5)",
    "CREATE INDEX breach_name IF NOT EXISTS FOR (b:Breach) ON (b.name)",
    "CREATE CONSTRAINT person_id IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT email_id IF NOT EXISTS FOR (e:Email) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT username_id IF NOT EXISTS FOR (u:Username) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT domain_id IF NOT EXISTS FOR (d:Domain) REQUIRE d.id IS UNIQUE",
    "CREATE CONSTRAINT ip_id IF NOT EXISTS FOR (i:IP) REQUIRE i.id IS UNIQUE",
]


class Neo4jClient:
    """
    Async Neo4j driver wrapper for GOD_EYE graph operations.

    Wraps all common operations (create nodes, create edges, query).
    Handles connection pooling and error recovery transparently.
    """

    def __init__(self) -> None:
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Establish connection and create schema indexes."""
        try:
            self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
                max_connection_pool_size=20,
                connection_timeout=10.0,
            )
            await self._driver.verify_connectivity()
            await self._create_indexes()
            logger.info("neo4j_connected", uri=settings.neo4j_uri)
        except Exception as e:
            raise DatabaseError("neo4j", "connect", str(e)) from e

    async def disconnect(self) -> None:
        """Close the driver and all connections."""
        if self._driver:
            await self._driver.close()
            self._driver = None

    async def _create_indexes(self) -> None:
        """Create all indexes and constraints if they don't exist."""
        assert self._driver is not None
        async with self._driver.session() as session:
            for index_query in INDEXES:
                try:
                    await session.run(index_query)
                except Exception as e:
                    # Index may already exist with different syntax — log and continue
                    logger.debug("index_creation_note", query=index_query, note=str(e))

    def _session(self) -> AsyncSession:
        """Get a new async session."""
        assert self._driver is not None, "Call connect() first"
        return self._driver.session()

    # ── Node Creation ────────────────────────────────────────────

    async def create_person(
        self, name: str, metadata: dict[str, Any] | None = None, request_id: str | None = None
    ) -> str:
        """Create or merge a Person node. Returns the node ID."""
        node_id = str(uuid4())
        props = {"id": node_id, "name": name, "request_id": request_id, **(metadata or {})}
        query = """
        MERGE (p:Person {name: $name})
        ON CREATE SET p = $props
        ON MATCH SET p.request_id = $request_id
        RETURN p.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, name=name, props=props, request_id=request_id)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_email(self, address: str, properties: dict[str, Any] | None = None) -> str:
        """Create or merge an Email node. Returns the node ID."""
        node_id = str(uuid4())
        domain = address.split("@")[-1] if "@" in address else ""
        props = {
            "id": node_id,
            "address": address,
            "domain": domain,
            **(properties or {}),
        }
        query = """
        MERGE (e:Email {address: $address})
        ON CREATE SET e = $props
        RETURN e.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, address=address, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_username(
        self, handle: str, platform: str, properties: dict[str, Any] | None = None
    ) -> str:
        """Create or merge a Username node. Returns the node ID."""
        node_id = str(uuid4())
        props = {
            "id": node_id,
            "handle": handle,
            "platform": platform,
            **(properties or {}),
        }
        query = """
        MERGE (u:Username {handle: $handle, platform: $platform})
        ON CREATE SET u = $props
        ON MATCH SET u += $props
        RETURN u.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, handle=handle, platform=platform, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_domain(self, name: str, properties: dict[str, Any] | None = None) -> str:
        """Create or merge a Domain node."""
        node_id = str(uuid4())
        props = {"id": node_id, "name": name, **(properties or {})}
        query = """
        MERGE (d:Domain {name: $name})
        ON CREATE SET d = $props
        ON MATCH SET d += $props
        RETURN d.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, name=name, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_ip(self, address: str, properties: dict[str, Any] | None = None) -> str:
        """Create or merge an IP node."""
        node_id = str(uuid4())
        props = {"id": node_id, "address": address, **(properties or {})}
        query = """
        MERGE (i:IP {address: $address})
        ON CREATE SET i = $props
        ON MATCH SET i += $props
        RETURN i.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, address=address, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_location(
        self,
        lat: float | None,
        lon: float | None,
        address: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Create a Location node."""
        node_id = str(uuid4())
        props = {
            "id": node_id,
            "latitude": lat,
            "longitude": lon,
            "address": address,
            **(properties or {}),
        }
        query = """
        CREATE (l:Location $props)
        RETURN l.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_image(
        self, hash_md5: str, file_path: str, properties: dict[str, Any] | None = None
    ) -> str:
        """Create or merge an Image node."""
        node_id = str(uuid4())
        props = {
            "id": node_id,
            "hash_md5": hash_md5,
            "file_path": file_path,
            **(properties or {}),
        }
        query = """
        MERGE (img:Image {hash_md5: $hash_md5})
        ON CREATE SET img = $props
        RETURN img.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, hash_md5=hash_md5, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_breach(self, name: str, properties: dict[str, Any] | None = None) -> str:
        """Create or merge a Breach node."""
        node_id = str(uuid4())
        props = {"id": node_id, "name": name, **(properties or {})}
        query = """
        MERGE (b:Breach {name: $name})
        ON CREATE SET b = $props
        RETURN b.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, name=name, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    async def create_company(self, name: str, properties: dict[str, Any] | None = None) -> str:
        """Create or merge a Company node."""
        node_id = str(uuid4())
        props = {"id": node_id, "name": name, **(properties or {})}
        query = """
        MERGE (c:Company {name: $name})
        ON CREATE SET c = $props
        ON MATCH SET c += $props
        RETURN c.id AS id
        """
        async with self._session() as session:
            result = await session.run(query, name=name, props=props)
            record = await result.single()
        return record["id"] if record else node_id

    # ── Relationships ────────────────────────────────────────────

    async def link_nodes(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> bool:
        """
        Create a relationship between two nodes.

        Uses MERGE to avoid duplicate relationships.
        """
        props = properties or {}
        query = f"""
        MATCH (a {{id: $from_id}})
        MATCH (b {{id: $to_id}})
        MERGE (a)-[r:{relationship_type}]->(b)
        SET r += $props
        RETURN r
        """
        try:
            async with self._session() as session:
                result = await session.run(query, from_id=from_id, to_id=to_id, props=props)
                record = await result.single()
            return record is not None
        except Exception as e:
            logger.error(
                "link_nodes_failed",
                from_id=from_id,
                to_id=to_id,
                rel=relationship_type,
                error=str(e),
            )
            return False

    async def update_node(self, node_id: str, properties: dict[str, Any]) -> bool:
        """Update properties of an existing node."""
        query = """
        MATCH (n {id: $node_id})
        SET n += $props
        RETURN n
        """
        async with self._session() as session:
            result = await session.run(query, node_id=node_id, props=properties)
            record = await result.single()
        return record is not None

    # ── Queries ──────────────────────────────────────────────────

    async def query_target_graph(self, target_name: str, depth: int = 3) -> dict[str, Any]:
        """
        Query the full graph for a target up to given depth.

        Returns nodes and relationships as a dict.
        """
        query = f"""
        MATCH (p:Person {{name: $name}})-[r*1..{depth}]-(connected)
        RETURN p, r, connected
        """
        async with self._session() as session:
            result = await session.run(query, name=target_name)
            records = await result.data()
        return {"target": target_name, "graph": records}

    async def query_connections(self, node_id: str, depth: int = 2) -> list[dict[str, Any]]:
        """Find all nodes connected to a given node within depth."""
        query = f"""
        MATCH (n {{id: $node_id}})-[r*1..{depth}]-(connected)
        RETURN connected, r
        """
        async with self._session() as session:
            result = await session.run(query, node_id=node_id)
            return await result.data()

    async def find_email_breaches(self, email: str) -> list[dict[str, Any]]:
        """Find all breaches for an email address."""
        query = """
        MATCH (e:Email {address: $email})-[:EXPOSED_IN]->(b:Breach)
        RETURN e.address AS email, collect(b.name) AS breaches, count(b) AS breach_count
        """
        async with self._session() as session:
            result = await session.run(query, email=email)
            record = await result.single()
        return [dict(record)] if record else []

    async def get_person_summary(self, person_name: str) -> dict[str, Any]:
        """Get comprehensive summary of a person entity."""
        query = """
        MATCH (p:Person {name: $name})
        OPTIONAL MATCH (p)-[:HAS_EMAIL]->(e:Email)-[:EXPOSED_IN]->(b:Breach)
        OPTIONAL MATCH (p)-[:HAS_ACCOUNT]->(u:Username)
        OPTIONAL MATCH (p)-[:APPEARS_IN]->(img:Image)
        OPTIONAL MATCH (p)-[:LOCATED_AT]->(loc:Location)
        OPTIONAL MATCH (p)-[:WORKS_AT]->(c:Company)
        RETURN
            p.name AS name,
            p.risk_score AS risk_score,
            count(DISTINCT b) AS breach_count,
            count(DISTINCT u) AS platform_count,
            count(DISTINCT img) AS image_count,
            collect(DISTINCT u.platform) AS platforms,
            collect(DISTINCT loc.city) AS cities,
            collect(DISTINCT c.name) AS employers
        """
        async with self._session() as session:
            result = await session.run(query, name=person_name)
            record = await result.single()
        return dict(record) if record else {}

    async def run_cypher(
        self, query: str, parameters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """
        Run a raw Cypher query with parameters.

        ONLY use this for queries not covered by the above methods.
        Always use parameterized queries — never string interpolation.
        """
        async with self._session() as session:
            result = await session.run(query, parameters or {})
            return await result.data()

    async def health_check(self) -> bool:
        """Check if the Neo4j connection is healthy."""
        try:
            async with self._session() as session:
                result = await session.run("RETURN 1 AS health")
                record = await result.single()
            return record is not None
        except Exception:
            return False


# ── Singleton ─────────────────────────────────────────────────────
_neo4j: Neo4jClient | None = None


async def get_neo4j() -> Neo4jClient:
    """Get or create the global Neo4j client instance."""
    global _neo4j
    if _neo4j is None:
        _neo4j = Neo4jClient()
        await _neo4j.connect()
    return _neo4j
