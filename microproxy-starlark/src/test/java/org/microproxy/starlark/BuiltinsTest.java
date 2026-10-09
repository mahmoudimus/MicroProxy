package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;

class BuiltinsTest {

    private static StarlarkScript run(String source) throws ScriptException {
        return StarlarkScript.compile(source, "test.star", StarlarkScript.Limits.DEFAULT);
    }

    private static void check(String... lines) throws ScriptException {
        // Starlark allows if statements only inside functions.
        StringBuilder src = new StringBuilder("def checks():\n");
        for (String line : lines) {
            src.append("    ").append(line).append('\n');
        }
        run(src.append("checks()\n").toString());
    }

    @Test
    void regularExpressions() throws ScriptException {
        check(
                "m = re.match(r'(\\w+)-(?P<num>\\d+)', 'abc-123x')",
                "if m.group(1) != 'abc' or m.group('num') != '123' or m.group() != 'abc-123': fail('match', m.groups())",
                "if m.start('num') != 4 or m.end() != 7: fail('offsets')",
                "if m.groupdict() != {'num': '123'}: fail('groupdict')",
                "if re.match('x', 'ax') != None: fail('match is anchored')",
                "if re.search('x', 'ax') == None: fail('search')",
                "if re.fullmatch('a.', 'abc') != None: fail('fullmatch')",
                "if re.sub(r'(\\d+)', r'<\\1>', 'a1b22') != 'a<1>b<22>': fail('sub template')",
                "if re.sub(r'(?P<d>\\d)', r'\\g<d>\\g<d>', 'a1', count=1) != 'a11': fail('sub named')",
                "if re.sub('x', lambda m: m.group(0).upper(), 'axbx') != 'aXbX': fail('sub function')",
                "if re.sub('x*', '-', 'abc') != '-a-b-c-': fail('sub empty', re.sub('x*', '-', 'abc'))",
                "if re.findall(r'\\d', 'a1b2') != ['1', '2']: fail('findall')",
                "if re.findall(r'(\\w)=(\\d)', 'a=1 b=2') != [('a', '1'), ('b', '2')]: fail('findall groups')",
                "if re.split(r',\\s*', 'a, b,c') != ['a', 'b', 'c']: fail('split')",
                "if re.split(r'(,)', 'a,b', maxsplit=1) != ['a', ',', 'b']: fail('split groups')",
                "if not re.match(re.escape('a.b'), 'a.b') or re.match(re.escape('a.b'), 'axb'): fail('escape')",
                "if re.match('(?i)HELLO', 'hello') == None: fail('inline flags')");
    }

    @Test
    void catastrophicRegexStopsAtTheDeadline() throws Exception {
        StarlarkScript s = StarlarkScript.compile(
                "def f():\n    return re.match('(.*a){12}x', 'a' * 30)\n", "slow.star",
                new StarlarkScript.Limits(1_000_000, Duration.ofMillis(200)));
        long start = System.nanoTime();
        EvalException e = assertThrows(EvalException.class, () -> s.call("f", Mutability.create("t")));
        assertTrue(e.getMessage().contains("deadline"), e.getMessage());
        assertTrue(System.nanoTime() - start < Duration.ofSeconds(5).toNanos());
    }

    @Test
    void stepLimitStopsLoops() throws Exception {
        StarlarkScript s = StarlarkScript.compile(
                "def f():\n    n = 0\n    for i in range(100000000):\n        n += i\n    return n\n", "loop.star",
                new StarlarkScript.Limits(10_000, Duration.ofSeconds(30)));
        EvalException e = assertThrows(EvalException.class, () -> s.call("f", Mutability.create("t")));
        assertTrue(e.getMessage().contains("too many steps"), e.getMessage());
    }

    @Test
    void encodingsAndDigests() throws ScriptException {
        check(
                "if base64.encode('hi') != 'aGk=': fail('b64')",
                "if codecs.decode(base64.decode('aGk')) != 'hi': fail('b64 decode without padding')",
                "if base64.encode(codecs.encode('\\u00ff\\u00fe', 'latin1'), urlsafe=True) != '__4=': fail('urlsafe')",
                "if digest.sha256('abc') != 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad': fail('sha256')",
                "if digest.md5('') != 'd41d8cd98f00b204e9800998ecf8427e': fail('md5')",
                "if digest.hmac_sha256('key', 'The quick brown fox jumps over the lazy dog') != "
                        + "'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8': fail('hmac')",
                "if url.quote('a b/c?') != 'a%20b/c%3F' or url.quote('a/b', safe='') != 'a%2Fb': fail('quote')",
                "if url.unquote('a%20b+c') != 'a b+c': fail('unquote')",
                "if url.parse_query('a=1&a=2&b=x+y&c') != {'a': ['1', '2'], 'b': ['x y'], 'c': ['']}: fail('parse_query')",
                "if url.encode_query({'a': '1 2', 'b': ['x', 'y']}) != 'a=1%202&b=x&b=y': fail('encode_query')",
                "if json.decode(json.encode({'a': [1, 2]}))['a'][1] != 2: fail('json')",
                "if time.now() < 1e9 or time.monotonic() <= 0: fail('time')");
    }

    @Test
    void constantTimeEquality() throws ScriptException {
        check(
                "if not digest.equal('secret', 'secret'): fail('equal strings')",
                "if digest.equal('secret', 'secreT') or digest.equal('secret', 'secret2'): fail('different strings')",
                "if not digest.equal(b'\\x00\\xff', b'\\x00\\xff') or digest.equal(b'a', b'b'): fail('bytes')",
                "if not digest.equal('\u00e9', b'\\xc3\\xa9'): fail('strings compare as UTF-8')",
                "if not digest.equal('', b''): fail('empty')",
                "if not digest.equal(digest.sha256('token'), digest.sha256(b'token')): fail('digests')");
        ScriptException e = assertThrows(ScriptException.class, () -> check("digest.equal('a', 1)"));
        assertTrue(e.getMessage().contains("b must be bytes or string, not int"), e.getMessage());
    }

    @Test
    void responseBuiltin() throws ScriptException {
        check(
                "r = response(404, 'nope', headers={'X-A': 'b'})",
                "if r.status != 404 or r.text != 'nope' or r.headers['x-a'] != 'b': fail('response')",
                "if not r.headers['content-type'].startswith('text/plain'): fail('content type')",
                "if response(content_type='application/json', body='{}').headers.get('Content-Type') != 'application/json': fail('ct')",
                "r.status = 201",
                "r.text = 'changed'",
                "if r.status != 201 or r.body != bytes('changed'): fail('assign')");
    }

    @Test
    void scriptsCannotMutateGlobalsFromHooks() throws Exception {
        StarlarkScript s = run("seen = []\ndef f():\n    seen.append(1)\n");
        EvalException e = assertThrows(EvalException.class, () -> s.call("f", Mutability.create("t")));
        assertTrue(e.getMessage().contains("frozen") || e.getMessage().contains("immutable"), e.getMessage());
    }

    @Test
    void syntaxAndRuntimeErrorsAreReported() {
        ScriptException syntax = assertThrows(ScriptException.class, () -> run("def f(:\n"));
        assertTrue(syntax.getMessage().contains("test.star"), syntax.getMessage());
        ScriptException runtime = assertThrows(ScriptException.class, () -> run("x = 1 // 0\n"));
        assertTrue(runtime.getMessage().contains("division by zero"), runtime.getMessage());
    }

    @Test
    void definesOnlyFunctions() throws ScriptException {
        StarlarkScript s = run("on_request = 1\ndef on_response(req, res, ctx):\n    pass\n");
        assertFalse(s.defines("on_request"));
        assertTrue(s.defines("on_response"));
        assertEquals("test.star", s.name());
    }
}
