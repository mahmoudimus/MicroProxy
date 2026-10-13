package org.microproxy.loadtest.client;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * The orchestrator's handle on the load generator's JVM: sends it a command and waits for its
 * answer (see {@link LoadClient}).
 */
public final class ClientControl implements AutoCloseable {

    private final ManagedProcess process;

    /** Wraps a started {@code client} process. */
    public ClientControl(ManagedProcess process) {
        this.process = process;
    }

    /** The load generator's process. */
    public ManagedProcess process() {
        return process;
    }

    /**
     * Sends {@code cmd} and returns the answer; throws if the load generator does not answer
     * within {@code timeout}, dies, or reports an error.
     */
    public Map<String, Object> call(Map<String, Object> cmd, Duration timeout) throws IOException, InterruptedException {
        process.send(Json.write(cmd));
        String line = process.nextProtocolLine(timeout);
        if (line == null) {
            throw new IOException("the load generator did not answer " + cmd.get("cmd") + " within " + timeout
                    + (process.alive() ? "" : " (it exited with " + process.exitCode() + "; see " + process.log() + ")"));
        }
        Map<String, Object> reply = Json.parseObject(line);
        if (reply.containsKey("error")) throw new IOException("load generator: " + reply.get("error"));
        return reply;
    }

    @Override
    public void close() {
        try {
            if (process.alive()) {
                process.send("{\"cmd\":\"exit\"}");
                process.waitFor(Duration.ofSeconds(5));
            }
        } catch (IOException | InterruptedException e) {
            // Killed below.
        }
        process.close();
    }
}
