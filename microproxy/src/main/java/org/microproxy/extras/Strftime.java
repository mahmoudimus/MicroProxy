package org.microproxy.extras;

import java.util.ArrayList;
import java.util.List;

/**
 * A subset of {@code strftime}, compiled once, that renders epoch milliseconds in UTC without
 * allocating: the time formats of {@code %START_TIME(...)%}. Conversions: {@code %Y %y %C %m %d
 * %e %j %H %I %M %S %p %b %h %B %a %A %u %w %z %Z %s %T %F %D %R %n %t %%}, and {@code %f} or
 * {@code %1f} to {@code %9f} for the fraction of the second (9 digits by default; digits beyond
 * milliseconds are zeros). Anything else is copied as it is.
 */
final class Strftime {

    private static final String[] MONTHS = {"January", "February", "March", "April", "May", "June", "July",
        "August", "September", "October", "November", "December"};
    private static final int[] DAYS_BEFORE_MONTH = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    private static final String[] DAYS = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday"};

    /** One piece of the format: a literal ({@code text} set) or a conversion ({@code conversion} and {@code digits}). */
    private record Piece(String text, char conversion, int digits) {}

    private final Piece[] pieces;

    private Strftime(Piece[] pieces) {
        this.pieces = pieces;
    }

    static Strftime compile(String format) {
        List<Piece> pieces = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        for (int i = 0; i < format.length(); i++) {
            char c = format.charAt(i);
            if (c != '%' || i + 1 >= format.length()) {
                literal.append(c);
                continue;
            }
            char next = format.charAt(i + 1);
            int digits = -1;
            int end = i + 1;
            if (next >= '1' && next <= '9' && i + 2 < format.length() && format.charAt(i + 2) == 'f') {
                digits = next - '0';
                next = 'f';
                end = i + 2;
            }
            if ("YyCmdejHIMSpbhBaAuwzZsTFDRntf%".indexOf(next) < 0) {
                literal.append(c);
                continue;
            }
            if (next == '%' || next == 'n' || next == 't') {
                literal.append(next == '%' ? '%' : next == 'n' ? '\n' : '\t');
                i = end;
                continue;
            }
            if (!literal.isEmpty()) {
                pieces.add(new Piece(literal.toString(), '\0', 0));
                literal.setLength(0);
            }
            pieces.add(new Piece(null, next, next == 'f' && digits < 0 ? 9 : digits));
            i = end;
        }
        if (!literal.isEmpty()) pieces.add(new Piece(literal.toString(), '\0', 0));
        return new Strftime(pieces.toArray(Piece[]::new));
    }

    /** Appends {@code epochMillis} as the format says, in UTC. */
    void format(long epochMillis, StringBuilder out) {
        long seconds = Math.floorDiv(epochMillis, 1000);
        int millis = (int) Math.floorMod(epochMillis, 1000);
        long days = Math.floorDiv(seconds, 86400);
        int secondOfDay = (int) Math.floorMod(seconds, 86400);
        // Civil date from days since 1970-01-01 (proleptic Gregorian).
        long z = days + 719468;
        long era = Math.floorDiv(z, 146097);
        long doe = z - era * 146097;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        int day = (int) (doy - (153 * mp + 2) / 5 + 1);
        int month = (int) (mp < 10 ? mp + 3 : mp - 9);
        long year = yoe + era * 400 + (month <= 2 ? 1 : 0);
        int hour = secondOfDay / 3600;
        int minute = secondOfDay / 60 % 60;
        int second = secondOfDay % 60;
        int weekday = (int) Math.floorMod(days + 4, 7);
        for (Piece p : pieces) {
            if (p.text() != null) {
                out.append(p.text());
                continue;
            }
            switch (p.conversion()) {
                case 'Y' -> out.append(year);
                case 'y' -> pad(out, (int) Math.floorMod(year, 100), 2);
                case 'C' -> pad(out, (int) Math.floorDiv(year, 100), 2);
                case 'm' -> pad(out, month, 2);
                case 'd' -> pad(out, day, 2);
                case 'e' -> {
                    if (day < 10) out.append(' ');
                    out.append(day);
                }
                case 'j' -> pad(out, dayOfYear(year, month, day), 3);
                case 'H' -> pad(out, hour, 2);
                case 'I' -> pad(out, hour % 12 == 0 ? 12 : hour % 12, 2);
                case 'M' -> pad(out, minute, 2);
                case 'S' -> pad(out, second, 2);
                case 'p' -> out.append(hour < 12 ? "AM" : "PM");
                case 'b', 'h' -> out.append(MONTHS[month - 1], 0, 3);
                case 'B' -> out.append(MONTHS[month - 1]);
                case 'a' -> out.append(DAYS[weekday], 0, 3);
                case 'A' -> out.append(DAYS[weekday]);
                case 'u' -> out.append(weekday == 0 ? 7 : weekday);
                case 'w' -> out.append(weekday);
                case 'z' -> out.append("+0000");
                case 'Z' -> out.append("UTC");
                case 's' -> out.append(seconds);
                case 'T' -> {
                    pad(out, hour, 2);
                    out.append(':');
                    pad(out, minute, 2);
                    out.append(':');
                    pad(out, second, 2);
                }
                case 'R' -> {
                    pad(out, hour, 2);
                    out.append(':');
                    pad(out, minute, 2);
                }
                case 'F' -> {
                    out.append(year).append('-');
                    pad(out, month, 2);
                    out.append('-');
                    pad(out, day, 2);
                }
                case 'D' -> {
                    pad(out, month, 2);
                    out.append('/');
                    pad(out, day, 2);
                    out.append('/');
                    pad(out, (int) Math.floorMod(year, 100), 2);
                }
                case 'f' -> fraction(out, millis, p.digits());
                default -> throw new IllegalStateException("conversion " + p.conversion());
            }
        }
    }

    private static int dayOfYear(long year, int month, int day) {
        boolean leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        return DAYS_BEFORE_MONTH[month - 1] + day + (leap && month > 2 ? 1 : 0);
    }

    /** The first {@code digits} digits of the fraction of a second that is {@code millis} milliseconds. */
    private static void fraction(StringBuilder out, int millis, int digits) {
        for (int i = 0; i < digits; i++) {
            int digit = i == 0 ? millis / 100 : i == 1 ? millis / 10 % 10 : i == 2 ? millis % 10 : 0;
            out.append((char) ('0' + digit));
        }
    }

    private static void pad(StringBuilder out, int value, int width) {
        int digits = value < 10 ? 1 : value < 100 ? 2 : value < 1000 ? 3 : 4;
        for (int i = digits; i < width; i++) out.append('0');
        out.append(value);
    }
}
