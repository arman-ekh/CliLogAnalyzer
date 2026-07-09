import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

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
            String line;
            long totalLines = 0;


            while((line = br.readLine()) != null){
                if(line.isEmpty()){
                    continue;
                }

                totalLines++;
            }
            System.out.println("total lines :" + totalLines);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }



    }
}