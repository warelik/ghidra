from pathlib import Path
import sys
import pyghidra


work = Path("/workspace")
if len(sys.argv) != 2 or sys.argv[1] not in {"create", "verify"}:
    raise SystemExit("Usage: smoke.py create|verify")
mode = sys.argv[1]
pyghidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType


project_context = (pyghidra.open_project(work, "Smoke", create=True) if mode == "create"
                   else pyghidra.open_project(work, "Smoke"))
with project_context as project:
    fixture = project.getProjectData().getFile("/fixture")
    if mode == "create":
        assert fixture is None, "Fresh smoke workspace unexpectedly has an imported program"
        loader = pyghidra.program_loader().project(project).source(str(work / "fixture"))
        with loader.load() as results:
            results.save(pyghidra.task_monitor())
        with pyghidra.program_context(project, "/fixture") as program:
            pyghidra.analyze(program)
            program.save("Initial analysis", pyghidra.task_monitor())
    else:
        assert fixture is not None, "Imported program did not persist across processes"
    with pyghidra.program_context(project, "/fixture") as program:
        functions = program.getFunctionManager().getFunctions(True)
        found = None
        expected_name = ("ghidra_fixture_add" if mode == "create"
                         else "ghidra_fixture_checked")
        while functions.hasNext():
            function = functions.next()
            if function.getName() == expected_name:
                found = function
                break
        assert found is not None, f"Required {expected_name} function was not recovered"
        if mode == "verify":
            assert found.getComment() == "Verified PyGhidra persistence", \
                "Function comment did not persist across processes"
        assert program.getListing().getInstructionAt(found.getEntryPoint()) is not None
        assert program.getReferenceManager().getReferencesTo(found.getEntryPoint()).hasNext()
        decompiler = DecompInterface()
        try:
            assert decompiler.openProgram(program)
            result = decompiler.decompileFunction(found, 60, pyghidra.task_monitor())
            assert result.decompileCompleted(), result.getErrorMessage()
            assert "return" in result.getDecompiledFunction().getC()
        finally:
            decompiler.dispose()
        if mode == "create":
            with pyghidra.transaction(program, "Annotate fixture"):
                found.setName("ghidra_fixture_checked", SourceType.USER_DEFINED)
                found.setComment("Verified PyGhidra persistence")
            program.save("Save fixture annotation", pyghidra.task_monitor())

if mode == "create":
    with pyghidra.open_project(work, "Smoke") as project:
        with pyghidra.program_context(project, "/fixture") as program:
            functions = program.getFunctionManager().getFunctions(True)
            persisted = None
            while functions.hasNext():
                function = functions.next()
                if function.getName() == "ghidra_fixture_checked":
                    persisted = function
                    break
            assert persisted is not None, "Rename did not survive project reopen"
            assert persisted.getComment() == "Verified PyGhidra persistence"

print(f"Ghidra smoke {mode} passed")
