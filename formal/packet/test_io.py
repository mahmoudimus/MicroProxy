import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import bytecode_guard as guard

JDK = Path(os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))


class AddressPolicy(unittest.TestCase):
    def method(self, body):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        source = root / 'Fixture.java'
        source.write_text('import java.nio.ByteBuffer; public class Fixture { '
                          'public static long run(ByteBuffer packet,int offset,long secret) {' + body + '} }')
        subprocess.run([str(JDK / 'bin/javac'), '--release', '21', '-d', str(root), str(source)], check=True, capture_output=True)
        return guard.disassemble(JDK / 'bin/javap', root, 'Fixture')['run']

    def test_secret_values_at_public_addresses_are_allowed(self):
        method = self.method('packet.put(offset,(byte)secret); return packet.get(offset+3);')
        self.assertEqual(['buffer-write', 'buffer-read'], guard.check_io(method, True, (2,)))

    def test_secret_address_is_rejected(self):
        method = self.method('return packet.get(offset+(int)secret);')
        with self.assertRaisesRegex(RuntimeError, 'secret buffer address'):
            guard.check_io(method, True, (2,))

    def test_secret_branch_is_rejected(self):
        method = self.method('if(secret==0) return packet.get(offset); return packet.get(offset+1);')
        with self.assertRaisesRegex(RuntimeError, 'opcode'):
            guard.check_io(method, True, (2,))

    def test_unknown_lookup_cannot_be_hidden_in_a_call(self):
        method = self.method('return Long.bitCount(secret);')
        with self.assertRaisesRegex(RuntimeError, 'Unlisted adapter call'):
            guard.check_io(method, True, (2,))

    def test_lookalike_or_wrong_signature_kernel_is_rejected(self):
        for owner, descriptor in (
                ('attacker/internal/verified/__default', '()J'),
                ('io/github/mahmoudimus/quic/internal/verified/__default', '()J')):
            method = {'owner': 'Fixture', 'descriptor': '()J', 'handler': False,
                      'instructions': [(0, 'invokestatic', '#1 // Method '+owner+'.Unprotect:'+descriptor),
                                       (3, 'lreturn', '')]}
            with self.subTest(owner=owner), self.assertRaisesRegex(RuntimeError, 'Unlisted adapter call'):
                guard.check_io(method, True)


if __name__ == '__main__':
    unittest.main()


class LengthValidation(unittest.TestCase):
    def code(self, maximum=4):
        return {'descriptor': '(I)V', 'flags': {'static'}, 'handler': False,
                'instructions': [(0,'iload_0',''), (1,'iconst_1',''), (2,'if_icmplt','10'),
                                 (5,'iload_0',''), (6,'iconst_'+str(maximum),''), (7,'if_icmple','24'),
                                 (10,'new','exception'), (24,'return','')]}

    def test_full_legal_domain_has_a_single_validation_trace(self):
        self.assertEqual(['if_icmplt-not-taken','if_icmple-taken'], guard.check_length_guard(self.code()))

    def test_narrowed_domain_branch_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'legal secret domain'):
            guard.check_length_guard(self.code(3))

    def test_call_on_valid_path_is_rejected(self):
        code = self.code()
        code['instructions'][-1] = (24,'invokestatic','hidden')
        with self.assertRaisesRegex(RuntimeError, 'Unlisted'):
            guard.check_length_guard(code)
