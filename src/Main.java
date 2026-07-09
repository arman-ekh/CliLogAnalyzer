import enums.LogRegex;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Error: No file path provided.");
            System.out.println("Usage: java Main <path_to_access_log>");
            System.exit(1);
        }

        String filePath = args[0];
        File logFile = new File(filePath);

        if (!logFile.exists()) {
            System.err.printf("Error: File '%s' does not exist.%n", filePath);
            System.exit(1);
        }

        if (logFile.isDirectory()) {
            System.err.printf("Error: '%s' is a directory. Please provide a valid log file.%n", filePath);
            System.exit(1);
        }

        if (!logFile.canRead()) {
            System.err.printf("Error: File '%s' is not readable (Permission denied).%n", filePath);
            System.exit(1);
        }

        System.out.println("File is ready to analyze");

        try (BufferedReader br = new BufferedReader(new FileReader(logFile))){
            String line = "";
            long totalLines = 0;

            long malformedLines = 0;
            long invalidIps = 0;
            long invalidDates = 0;
            long invalidRequests = 0;

            Pattern structPat = Pattern.compile(LogRegex.STRUCTURE.getPattern());
            Pattern ipPat = Pattern.compile(LogRegex.IP.getPattern());
            Pattern datePat = Pattern.compile(LogRegex.DATE.getPattern());
            Pattern reqPat = Pattern.compile(LogRegex.REQUEST_LINE.getPattern());


            Set<String> uniqueIps = new HashSet<>();
            Map<String, Long> pathCounter = new HashMap<>();

            while((line = br.readLine()) != null){
                if(line.isEmpty()){
                    continue;
                }
                totalLines++;

                Matcher structMatcher = structPat.matcher(line);

                if (!structMatcher.matches()) {
                    malformedLines++;
                    continue;
                }


                String rawIp = structMatcher.group(1);
                String rawDate = structMatcher.group(2);
                String rawRequest = structMatcher.group(3);
                String rawStatus = structMatcher.group(4);
                String rawSize = structMatcher.group(5);

                if (!ipPat.matcher(rawIp).matches()) {
                    invalidIps++;
                    continue;
                }

                uniqueIps.add(rawIp);


                if (!datePat.matcher(rawDate).matches()) {
                    invalidDates++;
                    continue;
                }


                if (!reqPat.matcher(rawRequest).matches()) {
                    invalidRequests++;
                    continue;
                }



                String[] requestParts = rawRequest.split(" ");
                String endpointPath = requestParts[1];

                pathCounter.put(endpointPath, pathCounter.getOrDefault(endpointPath, 0L) + 1);






            }

            System.out.println("Total lines : " + totalLines);
            System.out.println("Malformed lines : " + malformedLines);
            System.out.println("Number of unique Ips : "+uniqueIps.size());
            System.out.println("\n--- Top 10 Most Visited Endpoints ---");
            System.out.printf("%-10s | %s%n", "Requests", "Endpoint Path");
            System.out.println("--------------------------------------------------");

            pathCounter.entrySet().stream()
                    .sorted((e1, e2) -> Long.compare(e2.getValue(), e1.getValue()))
                    .limit(10)
                    .forEach(e -> System.out.printf("%,-10d | %s%n", e.getValue(), e.getKey()));


        } catch (IOException e) {
            throw new RuntimeException(e);
        }



    }
}