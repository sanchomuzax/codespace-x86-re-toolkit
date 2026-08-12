// Minimal headless GhidraScript smoke test.
import ghidra.app.script.GhidraScript;

public class HelloScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("CODESPACE_X86_RE_SCRIPT_OK");
    }
}
