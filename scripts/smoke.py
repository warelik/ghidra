from pathlib import Path
import pyghidra


work = Path("/workspace")
pyghidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType


with pyghidra.open_project(work, "Smoke", create=True) as project:
    if not project.getProjectData().getFile("/fixture"):
        loader = pyghidra.program_loader().project(project).source(str(work / "fixture"))
        with loader.load() as results:
            results.save(pyghidra.task_monitor())
        with pyghidra.program_context(project, "/fixture") as program:
            pyghidra.analyze(program)
            program.save("Initial analysis", pyghidra.task_monitor())
    with pyghidra.program_context(project, "/fixture") as program:
        functions = program.getFunctionManager().getFunctions(True)
        found = None
        while functions.hasNext():
            function = functions.next()
            if function.getName() in {"ghidra_fixture_add", "ghidra_fixture_checked"}:
                found = function
                break
        assert found is not None, "Fixture function not recovered"
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
        with pyghidra.transaction(program, "Annotate fixture"):
            found.setName("ghidra_fixture_checked", SourceType.USER_DEFINED)
            found.setComment("Verified PyGhidra persistence")
        program.save("Save fixture annotation", pyghidra.task_monitor())

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

print("Ghidra import, instructions, xrefs, decompilation, annotation and reopen passed")
