package enums;

public enum LogRegex {

    STRUCTURE("^(\\S+) - - \\[(.+?)\\] \"(.+?)\" (\\d{3}) (\\d+|-).*$"),

    IP("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),

    DATE("^\\d{2}/[A-Z][a-z]{2}/\\d{4}:\\d{2}:\\d{2}:\\d{2} [+\\-]\\d{4}$"),

    REQUEST_LINE("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \\S+ HTTP/\\d\\.\\d$");

    private final String pattern;

    LogRegex(String pattern) {
        this.pattern = pattern;
    }

    public String getPattern() {
        return pattern;
    }
}