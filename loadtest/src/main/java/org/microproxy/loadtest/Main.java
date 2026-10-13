package org.microproxy.loadtest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.microproxy.loadtest.client.LoadClient;
import org.microproxy.loadtest.origin.OriginServer;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.report.Report;
import org.microproxy.loadtest.scenario.Orchestrator;

/**
 * The harness's single runnable jar, dispatched by sub-command:
 *
 * <ul>
 *   <li>{@code run}: the orchestrator — start the origin and, for each proxy and scenario, a fresh
 *       proxy JVM and load generator, then write the JSON results and the Markdown report;
 *   <li>{@code origin}: the origin server JVM;
 *   <li>{@code client}: the load generator JVM, driven over standard input by the orchestrator;
 *   <li>{@code littleproxy}: the LittleProxy launcher (so the baseline runs from this jar);
 *   <li>{@code report}: re-render the report and charts from an existing results directory;
 *   <li>{@code env}: print the machine's limits and the tools found;
 *   <li>{@code help}: the settings and presets.
 * </ul>
 */
public final class Main {

    private Main() {}

    /** Dispatches the sub-command. */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            help();
            System.exit(2);
        }
        String command = args[0];
        List<String> rest = new ArrayList<>(Arrays.asList(args).subList(1, args.length));
        switch (command) {
            case "run" -> System.exit(Orchestrator.run(rest));
            case "origin" -> OriginServer.main(rest.toArray(String[]::new));
            case "client" -> LoadClient.main(rest.toArray(String[]::new));
            case "littleproxy" -> org.microproxy.loadtest.proxy.LittleProxyLauncher.main(rest.toArray(String[]::new));
            case "report" -> {
                Path dir = Path.of(rest.isEmpty() ? "loadtest/results/latest" : rest.get(0));
                Report.reRender(dir);
            }
            case "env" -> System.out.println(Json.pretty(Environment.describe()));
            case "help", "--help", "-h" -> help();
            default -> {
                System.err.println("unknown command: " + command);
                help();
                System.exit(2);
            }
        }
    }

    private static void help() {
        System.out.println("""
                MicroProxy load and capacity testing harness.

                Usage: java -jar microproxy-loadtest.jar <command> [options]

                Commands:
                  run      run the presets and scenarios, write results and the report
                  origin   the origin server (started by run)
                  client   the load generator (started by run)
                  littleproxy  the LittleProxy baseline launcher (started by run)
                  report <dir>  re-render the report and charts from a results directory
                  env      print the machine's limits and the external tools found
                  help     this help

                run options:
                  --preset <smoke|standard|full>   the size of the run (default smoke)
                  --out <dir>                       where results go (default loadtest/results)
                  --<setting> <value>               override a preset value (below)
                """);
        System.out.println("Settings (preset defaults shown):");
        System.out.println(Settings.help());
    }

    /** Whether a results directory exists (used by callers that re-render). */
    static boolean isResultsDir(Path dir) {
        return Files.isRegularFile(dir.resolve("results.json"));
    }
}
