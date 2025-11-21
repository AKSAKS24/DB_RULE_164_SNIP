from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(
    title="Rule Describe Table Modernization",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------
DESCRIBE_RE = re.compile(
    r"DESCRIBE\s+TABLE\s+(?P<table>\w+)\s+LINES\s+(?P<target>\w+)",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def extract_line(src: str, pos: int) -> str:
    ls = src.rfind("\n", 0, pos)
    if ls == -1:
        ls = 0
    else:
        ls += 1
    le = src.find("\n", pos)
    if le == -1:
        le = len(src)
    return src[ls:le].replace("\n", "\\n")


def make_finding(unit, src, start, table, target, original):
    abs_line = unit.start_line + src[:start].count("\n")
    snippet = extract_line(src, start)

    suggestion = f"Replace '{original}' with 'DATA({target}) = LINES( {table} )'."

    return Finding(
        prog_name=unit.pgm_name,
        incl_name=unit.inc_name,
        types=unit.type,
        blockname=unit.name,
        starting_line=abs_line,
        ending_line=abs_line,
        issues_type="ObsoleteDescribeTableUsage",
        severity="error",
        message=f"Obsolete 'DESCRIBE TABLE {table} LINES {target}' detected.",
        suggestion=suggestion,
        snippet=snippet,
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings = []

    for m in DESCRIBE_RE.finditer(src):
        table = m.group("table")
        target = m.group("target")
        start = m.start()
        original = m.group(0)
        findings.append(make_finding(unit, src, start, table, target, original))

    out = Unit(**unit.model_dump())
    out.findings = findings if findings else None
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def describe_array(units: List[Unit] = Body(...)):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def describe_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": "describe-table-modernization", "version": "2.0"}
