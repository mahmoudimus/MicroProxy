package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class ShakeTest {

    // {width, input length, first 32 output bytes, SHA-256 of the first 400 output bytes}, from
    // Python's hashlib.shake_128/shake_256 over bytes(i % 251 for i in range(length)); the lengths
    // straddle both rates (136 and 168 bytes)
    private static final String[][] VECTORS = {
        {"128", "0", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", "fc5f94401d3745ca41d8c8bc18afb9a8579a49fac1bc2cc449256c79ee4ee884"},
        {"128", "1", "0b784469a0628e03861cd8a196dfafa0e9e8056d04cddcc49f0746b9ad43ccb2", "90ff370cf2b3b157ab9fb2b2bca9b500de118ffdbac8844d796d1e1a87ed494b"},
        {"128", "135", "d11fafa27f42a8162b8ae013535771de81722c0abc8aa2bca01825462e2f8971", "7a773f849e6dc6de720bd4e5f6774334747f41796f5917b2a5b3fef9efe102fb"},
        {"128", "136", "30bdfd69382cab028173fba7c6d53878ec18081358e52c955dc6f5d52b60b029", "0dfc4c7266a49dc039d0a148d1fe6abd6bfbd8646e3e29de5ded6dd229a528e5"},
        {"128", "167", "1e552791cc4e93a0d4a8dc47ae49228c2faa869e40e628f6ace477aec3f1ca7a", "3f3053c4822ca012b6b09368f9e534e52d373f644cd4dfff6185f07e97b5fcce"},
        {"128", "168", "f15277eb61c4908d44a2853f3cde071ae2ed7a23461fbe162a1a98cf6875059c", "55064409f0db179101160f0d754bdf884cf9a49532c53d449703f95523f9b1c6"},
        {"128", "169", "015be3338c986d9846affa0f94b4afc2a76bc289c709e1a596ec9eccf090a773", "0ea6aa93de1a9ae0a97b77fcdec1c0d87ef5cfdd9e112b16818097267b5c9586"},
        {"128", "500", "ed9a5f1ed895f8f7cbad5bf512be2d884ffc10ee917ab8d4188b846b8063f533", "0ad79f13d110995a26c7da8360a7b8f315f2e67b42dd31946115da3c8030ef0a"},
        {"256", "0", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", "015ee5a941ab013a0f1abb9b1eceaad22aac013ae162a90dda87acd72683487b"},
        {"256", "1", "b8d01df855f7075882c636f6ddeacf41e5de0bbf30042ef0a86e36f4b8600d54", "9ab462a86fefa9e9556ed80316422f51e9d2ddd15b5885dbcc3d2102e2f5bb32"},
        {"256", "135", "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0", "92136e49bae838808b0ba8d9be25c90652565669fd32857133fe25b02c4a1dbb"},
        {"256", "136", "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a", "b6ca77c0cbab4c5416b416fc31ecb29c08827dead8fb094a5fd9b8987ff5e4c7"},
        {"256", "167", "989a61fbdb26d1695f841faaef850de4e5ca0095ea4c7511c54f0b0a098e8fad", "d7df65a3babb3bbab2ae93f931a3bf5a139f1dc696f331cdb239dbfdd7a55865"},
        {"256", "168", "1687771440dbcdaa8af7049dd319414a12a702caa4809a0ded089cb659219ea4", "660238f2a08e7a44ec1697c9739fbea1de3007d1fabd82cbfc6816e0539998ff"},
        {"256", "169", "d639f47fb6b6836625c047a8240313bba11e3b7e479595b43b48ecd35cc89e9e", "70d700a447ebfd49a1665ba332431e6809eaaa73cc45008862365c55981baa3e"},
        {"256", "500", "20a1c001eb6aee7535706c02dbe70f2a39d87d3fda665f89706bea6211025657", "76bf9be2e29ea5b105e9c72281616c5d201e9f94d6d062ef99ad328157e48f03"},
    };

    private static byte[] input(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (i % 251);
        return b;
    }

    private static Shake shake(String width) {
        return width.equals("128") ? Shake.shake128() : Shake.shake256();
    }

    @Test
    void matchesPythonsHashlib() throws Exception {
        HexFormat hex = HexFormat.of();
        for (String[] v : VECTORS) {
            Shake s = shake(v[0]);
            s.update(input(Integer.parseInt(v[1])));
            byte[] out = new byte[400];
            s.read(out);
            String what = "SHAKE" + v[0] + " of " + v[1] + " bytes";
            assertEquals(v[2], hex.formatHex(out, 0, 32), what);
            assertEquals(v[3], hex.formatHex(MessageDigest.getInstance("SHA-256").digest(out)), what);
        }
    }

    @Test
    void piecewiseInputAndOutputMatchOneShot() {
        byte[] data = input(500);
        Shake whole = Shake.shake128();
        whole.update(data);
        byte[] expected = new byte[700];
        whole.read(expected);

        Shake parts = Shake.shake128();
        for (int i = 0; i < data.length; i += 37) {
            parts.update(java.util.Arrays.copyOfRange(data, i, Math.min(data.length, i + 37)));
        }
        byte[] got = new byte[700];
        for (int i = 0; i < got.length; i += 24) {
            byte[] chunk = new byte[Math.min(24, got.length - i)];
            parts.read(chunk);
            System.arraycopy(chunk, 0, got, i, chunk.length);
        }
        assertArrayEquals(expected, got);
    }

    @Test
    void updateAfterReadIsRejected() {
        Shake s = Shake.shake256();
        s.read(new byte[1]);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> s.update(new byte[1]));
    }
}
