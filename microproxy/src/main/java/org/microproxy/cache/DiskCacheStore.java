package org.microproxy.cache;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.http.HttpHeaders;

/**
 * Keeps responses as files in a directory, so the cache survives restarts (and can serve while
 * offline). Each variant is one file named after a hash of its URL and {@code Vary} values,
 * written to a temporary file and moved into place. The index of what is stored lives in memory,
 * rebuilt from the files' headers at startup; the least recently used files go first when the
 * size limit is reached. One store should own its directory.
 */
public final class DiskCacheStore implements CacheStore {

    private static final System.Logger LOG = System.getLogger(DiskCacheStore.class.getName());
    private static final int MAGIC = 0x4D504331; // "MPC1"
    private static final String SUFFIX = ".entry";

    private final Path dir;
    private final long maxSize;
    private final ReentrantLock lock = new ReentrantLock();
    /** URL to its variants' files, by vary signature. */
    private final Map<String, Map<String, Meta>> index = new HashMap<>();
    /** Every file, least recently used first. */
    private final LinkedHashMap<Path, Meta> lru = new LinkedHashMap<>(16, 0.75f, true);
    private long size;
    private int count;

    // @value-candidate: becomes a value class in the valhalla build profile
    private record Meta(String key, String signature, Path file, long weight) {}

    /**
     * Opens (creating if needed) a store in {@code dir}, indexing the entries already there.
     *
     * @param maxSize the most {@link CachedResponse#weight()} to hold, in bytes
     *
     * @param dir the directory backing the response cache
     * @throws IOException if the cache directory cannot be created or read
     */
    public DiskCacheStore(Path dir, long maxSize) throws IOException {
        if (maxSize <= 0) throw new IllegalArgumentException("maxSize must be positive");
        this.dir = dir;
        this.maxSize = maxSize;
        Files.createDirectories(dir);
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                if (name.endsWith(".tmp")) {
                    Files.deleteIfExists(p);
                } else if (name.endsWith(SUFFIX)) {
                    files.add(p);
                }
            }
        }
        // Oldest first, so the access order reflects modification times.
        files.sort(Comparator.comparing(DiskCacheStore::modified));
        for (Path p : files) {
            try {
                CachedResponse r = read(p);
                index(r, p);
            } catch (IOException e) {
                LOG.log(Level.WARNING, "dropping unreadable cache file " + p + ": " + e);
                Files.deleteIfExists(p);
            }
        }
    }

    private static FileTime modified(Path p) {
        try {
            return Files.getLastModifiedTime(p);
        } catch (IOException e) {
            return FileTime.fromMillis(0);
        }
    }

    @Override
    public List<CachedResponse> get(String key) {
        List<Meta> metas;
        lock.lock();
        try {
            Map<String, Meta> variants = index.get(key);
            if (variants == null) return List.of();
            metas = new ArrayList<>(variants.values());
            for (Meta m : metas) lru.get(m.file());
        } finally {
            lock.unlock();
        }
        List<CachedResponse> out = new ArrayList<>(metas.size());
        for (Meta m : metas) {
            try {
                CachedResponse r = read(m.file());
                if (r.key().equals(key)) out.add(r);
            } catch (IOException e) {
                // Evicted or replaced meanwhile, or damaged: treat as a miss.
                LOG.log(Level.DEBUG, "cannot read " + m.file() + ": " + e.getMessage());
            }
        }
        out.sort(Comparator.comparingLong(CachedResponse::responseTime).reversed());
        return out;
    }

    @Override
    public void put(CachedResponse response) {
        if (response.weight() > maxSize) return;
        Path file = dir.resolve(fileName(response.key(), response.vary()));
        Path tmp = dir.resolve(file.getFileName() + "." + Thread.currentThread().threadId() + ".tmp");
        try {
            try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(tmp)))) {
                write(response, out);
            }
            lock.lock();
            try {
                try {
                    Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
                }
                unindex(response.key(), signature(response.vary()));
                index(response, file);
                evict(response.key());
            } finally {
                lock.unlock();
            }
        } catch (IOException e) {
            LOG.log(Level.WARNING, "cannot store " + response.key() + ": " + e.getMessage());
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {
                // nothing more to do
            }
        }
    }

    @Override
    public void remove(String key) {
        lock.lock();
        try {
            Map<String, Meta> variants = index.remove(key);
            if (variants == null) return;
            for (Meta m : variants.values()) {
                size -= m.weight();
                count--;
                lru.remove(m.file());
                delete(m.file());
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long size() {
        lock.lock();
        try {
            return size;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int count() {
        lock.lock();
        try {
            return count;
        } finally {
            lock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------

    private void index(CachedResponse r, Path file) {
        Meta m = new Meta(r.key(), signature(r.vary()), file, r.weight());
        index.computeIfAbsent(r.key(), k -> new LinkedHashMap<>()).put(m.signature(), m);
        lru.put(file, m);
        size += m.weight();
        count++;
    }

    private void unindex(String key, String signature) {
        Map<String, Meta> variants = index.get(key);
        if (variants == null) return;
        Meta old = variants.remove(signature);
        if (old != null) {
            size -= old.weight();
            count--;
            lru.remove(old.file());
        }
        if (variants.isEmpty()) index.remove(key);
    }

    /** Deletes least recently used files until the store fits, sparing {@code keep}'s variants. */
    private void evict(String keep) {
        if (size <= maxSize) return;
        List<Meta> victims = new ArrayList<>();
        long excess = size - maxSize;
        for (Meta m : lru.values()) {
            if (excess <= 0) break;
            if (m.key().equals(keep)) continue;
            victims.add(m);
            excess -= m.weight();
        }
        for (Meta m : victims) {
            unindex(m.key(), m.signature());
            delete(m.file());
        }
    }

    private static void delete(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            LOG.log(Level.DEBUG, "cannot delete " + file + ": " + e.getMessage());
        }
    }

    static String signature(Map<String, String> vary) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : new TreeMap<>(vary).entrySet()) {
            sb.append(e.getKey()).append('\0').append(e.getValue() == null ? "\1" : e.getValue()).append('\0');
        }
        return sb.toString();
    }

    private static String fileName(String key, Map<String, String> vary) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(key.getBytes(StandardCharsets.UTF_8));
            sha.update((byte) 0);
            sha.update(signature(vary).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(sha.digest(), 0, 20) + SUFFIX;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // File format: magic, then length-prefixed fields; the body last.
    // ---------------------------------------------------------------------------------------

    private static void write(CachedResponse r, DataOutputStream out) throws IOException {
        out.writeInt(MAGIC);
        writeString(out, r.key());
        out.writeLong(r.requestTime());
        out.writeLong(r.responseTime());
        out.writeInt(r.status());
        writeString(out, r.reason());
        out.writeInt(r.vary().size());
        for (Map.Entry<String, String> e : r.vary().entrySet()) {
            writeString(out, e.getKey());
            out.writeBoolean(e.getValue() != null);
            if (e.getValue() != null) writeString(out, e.getValue());
        }
        List<Map.Entry<String, String>> headers = r.headersUnsafe().entries();
        out.writeInt(headers.size());
        for (Map.Entry<String, String> e : headers) {
            writeString(out, e.getKey());
            writeString(out, e.getValue());
        }
        out.writeInt(r.bodyLength());
        out.write(r.bodyUnsafe());
    }

    private static CachedResponse read(Path file) throws IOException {
        try (InputStream raw = Files.newInputStream(file);
                DataInputStream in = new DataInputStream(new BufferedInputStream(raw))) {
            if (in.readInt() != MAGIC) throw new IOException("not a cache entry");
            String key = readString(in);
            long requestTime = in.readLong();
            long responseTime = in.readLong();
            int status = in.readInt();
            String reason = readString(in);
            int varyCount = in.readInt();
            if (varyCount < 0 || varyCount > 1000) throw new IOException("bad vary count");
            Map<String, String> vary = new HashMap<>();
            for (int i = 0; i < varyCount; i++) {
                String name = readString(in);
                vary.put(name, in.readBoolean() ? readString(in) : null);
            }
            int headerCount = in.readInt();
            if (headerCount < 0 || headerCount > 10_000) throw new IOException("bad header count");
            HttpHeaders headers = new HttpHeaders();
            for (int i = 0; i < headerCount; i++) {
                headers.add(readString(in), readString(in));
            }
            int length = in.readInt();
            if (length < 0) throw new IOException("bad body length");
            byte[] body = in.readNBytes(length);
            if (body.length != length) throw new IOException("truncated body");
            return new CachedResponse(key, vary, status, reason, headers, body, requestTime, responseTime);
        } catch (IllegalArgumentException e) {
            throw new IOException("invalid cache entry: " + e.getMessage(), e);
        }
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        out.writeInt(b.length);
        out.write(b);
    }

    private static String readString(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > 1 << 20) throw new IOException("bad string length");
        byte[] b = in.readNBytes(n);
        if (b.length != n) throw new IOException("truncated entry");
        return new String(b, StandardCharsets.UTF_8);
    }
}
