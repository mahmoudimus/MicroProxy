package org.microproxy.loadtest.proc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MachineNamesTest {

    @TempDir
    Path dir;

    @Test
    void searchDomainsLocalDomainAndHostNameAreFoundLongestFirst() throws IOException {
        Path resolv = Files.writeString(dir.resolve("resolv.conf"),
                "# generated\nnameserver 169.254.169.254\ndomain zone-a.c.project-1.internal\n"
                        + "search zone-a.c.project-1.internal c.project-1.internal google.internal\n");
        Path host = Files.writeString(dir.resolve("hostname"), "bench-vm\n");
        assertEquals(List.of("zone-a.c.project-1.internal", "c.project-1.internal", "google.internal", "bench-vm"),
                Environment.machineNames(resolv, host));
    }

    @Test
    void aLogLosesTheMachinesNames() throws IOException {
        Path log = Files.writeString(dir.resolve("squid.log"),
                "Adding domain zone-a.c.project-1.internal from /etc/resolv.conf\n"
                        + "Adding domain c.project-1.internal from /etc/resolv.conf\nAccepting HTTP connections\n");
        Environment.scrubMachineNames(log, List.of("zone-a.c.project-1.internal", "c.project-1.internal"));
        assertEquals("Adding domain <machine name> from /etc/resolv.conf\n"
                + "Adding domain <machine name> from /etc/resolv.conf\nAccepting HTTP connections\n", Files.readString(log));
    }

    @Test
    void missingFilesAreNoNames() {
        assertEquals(List.of(), Environment.machineNames(dir.resolve("none"), dir.resolve("none-either")));
    }
}
