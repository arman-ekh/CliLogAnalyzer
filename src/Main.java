import enums.LogRegex;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public class Main {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Error: No file path provided.");
            System.out.println("Usage: java Main <path_to_access_log>");
            System.exit(1);
        }

        String filePath ="";
        int topEndPointMax = 10;
        int startHour = 0; 
        int endHour = 23;
        for (int i = 0; i < args.length; i++) {
            if(args[i].equals("--top")){
                if (i + 1 < args.length) {
                    try {
                        topEndPointMax = Integer.parseInt(args[i + 1]);
                        if(topEndPointMax <= 0){
                            System.err.println("Error:--top command expects a positive integer");
                            System.exit(1);
                        }
                        i++;
                    } catch (NumberFormatException e) {
                        System.err.println("Error: Invalid number for --top. Please provide an integer.");
                        System.exit(1);
                    }
                }else {
                    System.err.println("Error: --top requires a number. Usage: --top <number>");
                    System.exit(1);
                }
            } else if (args[i].equals("--start")) {
                if (i + 1 < args.length) {
                    startHour = Integer.parseInt(args[i + 1]);
                    if (startHour < 0 || startHour > 23) {
                        System.err.println("Error: Start hour must be between 0 and 23.");
                        System.exit(1);
                    }
                    i++;
                }
            } else if (args[i].equals("--end")) {
                if (i + 1 < args.length) {
                    endHour = Integer.parseInt(args[i + 1]);
                    if (endHour < 0 || endHour > 23) {
                        System.err.println("Error: End hour must be between 0 and 23.");
                        System.exit(1);
                    }
                    i++;
                }
            } else {
                filePath = args[i];
            }
        }
        if (startHour > endHour) {
            System.err.println("Error: Start hour cannot be greater than End hour.");
            System.exit(1);
        }

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

        try {
            InputStream fileStream = new FileInputStream(logFile);

            if (logFile.getName().endsWith(".gz")) {
                fileStream = new GZIPInputStream(fileStream);
            }
            BufferedReader br = new BufferedReader(new InputStreamReader(fileStream, StandardCharsets.UTF_8));
            String line = "";
            long totalLines = 0;



            long malformedLines = 0;
            long invalidIps = 0;
            long invalidDates = 0;
            long invalidRequests = 0;
            long numberOfErrors4xx = 0;
            long numberOfErrors5xx = 0;
            long validRequests = 0;
            long[] numberOfRequestsPerHour = new long[24];
            long[] errors5xxPerHour = new long[24];

            Pattern structPat = Pattern.compile(LogRegex.STRUCTURE.getPattern());
            Pattern ipPat = Pattern.compile(LogRegex.IP.getPattern());
            Pattern datePat = Pattern.compile(LogRegex.DATE.getPattern());
            Pattern reqPat = Pattern.compile(LogRegex.REQUEST_LINE.getPattern());


            Set<String> uniqueIps = new HashSet<>();
            Map<String, Long> pathCounter = new HashMap<>();

            Map<String, Long> bruteForceTracker = new HashMap<>();
            final long SUSPICIOUS_THRESHOLD = 50;

            final double SPIKE_MULTIPLIER = 1.8;

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

                if (!datePat.matcher(rawDate).matches()) {
                    invalidDates++;
                    continue;
                }

                if (!reqPat.matcher(rawRequest).matches()) {
                    invalidRequests++;
                    continue;
                }

                //for limiting to start hour and end hour given by user
                int hour = Integer.parseInt(rawDate.substring(12, 14));
                if (hour < startHour || hour > endHour) {
                    continue;
                }

                validRequests++;

                //number of unique ips
                uniqueIps.add(rawIp);

                //number of Errors 4xx or 5xx
                if(rawStatus.length() == 3){
                    if(rawStatus.charAt(0) == '4'){
                        numberOfErrors4xx++;
                    } else if (rawStatus.charAt(0) == '5') {
                        numberOfErrors5xx++;
                    }
                }

                //top 10 most visited endpoints
                String[] requestParts = rawRequest.split(" ");
                String endpointPath = requestParts[1];

                pathCounter.put(endpointPath, pathCounter.getOrDefault(endpointPath, 0L) + 1);

                //number of requests per hour
                numberOfRequestsPerHour[hour]++;

                //looking for Suspicious Activity
                if (endpointPath.equals("/login") && rawStatus.equals("401")) {
                    bruteForceTracker.put(rawIp, bruteForceTracker.getOrDefault(rawIp, 0L) + 1);
                }

                //looking for high rate of 5xx errors
                if(rawStatus.length() == 3 && rawStatus.charAt(0) == '5'){
                     errors5xxPerHour[hour]++;
                }
            }

            System.out.println("\nTotal lines : " + totalLines);
            System.out.println("\nTotal valid logs : " + validRequests);
            System.out.println("\nMalformed lines : " + malformedLines);
            System.out.println("\nNumber of unique Ips : "+uniqueIps.size());
            System.out.println("\n--- Top " + topEndPointMax+" Most Visited Endpoints ---");
            System.out.printf("%-10s | %s%n", "Requests", "Endpoint Path");
            System.out.println("--------------------------------------------------");

            pathCounter.entrySet().stream()
                    .sorted((e1, e2) -> Long.compare(e2.getValue(), e1.getValue()))
                    .limit(topEndPointMax)
                    .forEach(e -> System.out.printf("%,-10d | %s%n", e.getValue(), e.getKey()));

            if(validRequests > 0){
                double errorPercentage4x = (double) numberOfErrors4xx / (validRequests)* 100;
                double errorPercentage5x = (double) numberOfErrors5xx / (validRequests) * 100;
                double totalErrorPercentage = ((double) (numberOfErrors4xx + numberOfErrors5xx) / validRequests) * 100;
                System.out.printf("\n4xx Client Errors : %,d (%.2f%%)%n", numberOfErrors4xx, errorPercentage4x);
                System.out.printf("5xx Server Errors : %,d (%.2f%%)%n", numberOfErrors5xx, errorPercentage5x);
                System.out.printf("Total Error Rate  : %,d (%.2f%%)%n", (numberOfErrors4xx + numberOfErrors5xx), totalErrorPercentage);
            }

            System.out.println("\n--- Hourly Traffic Distribution ---");
            System.out.printf("%-6s | %-10s | Histogram%n", "Hour", "Requests");
            System.out.println("--------------------------------------------------");

            long maxRequests = 0;
            for (long count : numberOfRequestsPerHour) {
                if (count > maxRequests) {
                    maxRequests = count;
                }
            }
            if (maxRequests == 0) maxRequests = 1;

            for (int h = 0; h < numberOfRequestsPerHour.length; h++) {
                long count = numberOfRequestsPerHour[h];

                int barLength = (int) (((double) count / maxRequests) * 30);
                String bar = "#".repeat(barLength);

                System.out.printf("%02d:00  | %-10s | %s%n", h, String.format("%,d", count), bar);
            }
            System.out.println("--------------------------------------------------");


            int numberOfHoursWithActivity = 0;
            double[] averageErrors5xxPerHour = new double[24];

            for(int h = 0; h < errors5xxPerHour.length;h++){
                long errorCount = errors5xxPerHour[h];
                long totalCount = numberOfRequestsPerHour[h];

                if(totalCount == 0){
                    totalCount = 1;
                }else{
                    numberOfHoursWithActivity++;
                }
                double errorPercentage = (double) errorCount / totalCount * 100;
                averageErrors5xxPerHour[h] = errorPercentage;
            }

            double average5xxPerHour = 0;
            for(int h = 0 ; h < averageErrors5xxPerHour.length ; h++){
                average5xxPerHour+=averageErrors5xxPerHour[h];
            }

            if (numberOfHoursWithActivity >= 1) {
                average5xxPerHour /= numberOfHoursWithActivity;


                for (int h = 0; h < averageErrors5xxPerHour.length; h++) {
                    if (averageErrors5xxPerHour[h] > SPIKE_MULTIPLIER * average5xxPerHour && errors5xxPerHour[h] > 5) {

                        System.out.println("\n[ANOMALY DETECTED] HTTP 5xx Error Spike");
                        System.out.printf("   Time Window       : %02d:00 - %02d:00%n", h, (h + 1) % 24);
                        System.out.printf("   Current Error Rate: %.2f%%%n", averageErrors5xxPerHour[h]);
                        System.out.printf("   Baseline Average  : %.2f%% (Trigger: > %.2f%%)%n",
                                average5xxPerHour, (average5xxPerHour * SPIKE_MULTIPLIER));
                        System.out.printf("   Raw Volume        : %,d errors out of %,d total requests%n",
                                errors5xxPerHour[h], numberOfRequestsPerHour[h]);
                        System.out.println("   ------------------------------------------------");
                    }
                }
            }






            for (Map.Entry<String, Long> entry : bruteForceTracker.entrySet()) {
                if (entry.getValue() > SUSPICIOUS_THRESHOLD) {
                    System.out.printf("\nALERT: IP [%s] detected with %,d failed login attempts!%n",
                            entry.getKey(), entry.getValue());
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }



    }
}