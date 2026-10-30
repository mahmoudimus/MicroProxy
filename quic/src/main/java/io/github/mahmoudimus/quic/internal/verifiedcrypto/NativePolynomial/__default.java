// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolynomialRing.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedPolynomial.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static int Len(int s) {
    if (java.lang.Integer.signum((s)) == 0) {
      return 128;
    } else if ((s) == (1)) {
      return 64;
    } else if ((s) == (2)) {
      return 32;
    } else if ((s) == (3)) {
      return 16;
    } else if ((s) == (4)) {
      return 8;
    } else if ((s) == (5)) {
      return 4;
    } else {
      return 2;
    }
  }
  public static int ZetasChunk0(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1;
    } else if ((i) == (1)) {
      return 1729;
    } else if ((i) == (2)) {
      return 2580;
    } else if ((i) == (3)) {
      return 3289;
    } else if ((i) == (4)) {
      return 2642;
    } else if ((i) == (5)) {
      return 630;
    } else if ((i) == (6)) {
      return 1897;
    } else if ((i) == (7)) {
      return 848;
    } else if ((i) == (8)) {
      return 1062;
    } else if ((i) == (9)) {
      return 1919;
    } else if ((i) == (10)) {
      return 193;
    } else if ((i) == (11)) {
      return 797;
    } else if ((i) == (12)) {
      return 2786;
    } else if ((i) == (13)) {
      return 3260;
    } else if ((i) == (14)) {
      return 569;
    } else {
      return 1746;
    }
  }
  public static int ZetasChunk1(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 296;
    } else if ((i) == (1)) {
      return 2447;
    } else if ((i) == (2)) {
      return 1339;
    } else if ((i) == (3)) {
      return 1476;
    } else if ((i) == (4)) {
      return 3046;
    } else if ((i) == (5)) {
      return 56;
    } else if ((i) == (6)) {
      return 2240;
    } else if ((i) == (7)) {
      return 1333;
    } else if ((i) == (8)) {
      return 1426;
    } else if ((i) == (9)) {
      return 2094;
    } else if ((i) == (10)) {
      return 535;
    } else if ((i) == (11)) {
      return 2882;
    } else if ((i) == (12)) {
      return 2393;
    } else if ((i) == (13)) {
      return 2879;
    } else if ((i) == (14)) {
      return 1974;
    } else {
      return 821;
    }
  }
  public static int ZetasChunk2(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 289;
    } else if ((i) == (1)) {
      return 331;
    } else if ((i) == (2)) {
      return 3253;
    } else if ((i) == (3)) {
      return 1756;
    } else if ((i) == (4)) {
      return 1197;
    } else if ((i) == (5)) {
      return 2304;
    } else if ((i) == (6)) {
      return 2277;
    } else if ((i) == (7)) {
      return 2055;
    } else if ((i) == (8)) {
      return 650;
    } else if ((i) == (9)) {
      return 1977;
    } else if ((i) == (10)) {
      return 2513;
    } else if ((i) == (11)) {
      return 632;
    } else if ((i) == (12)) {
      return 2865;
    } else if ((i) == (13)) {
      return 33;
    } else if ((i) == (14)) {
      return 1320;
    } else {
      return 1915;
    }
  }
  public static int ZetasChunk3(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 2319;
    } else if ((i) == (1)) {
      return 1435;
    } else if ((i) == (2)) {
      return 807;
    } else if ((i) == (3)) {
      return 452;
    } else if ((i) == (4)) {
      return 1438;
    } else if ((i) == (5)) {
      return 2868;
    } else if ((i) == (6)) {
      return 1534;
    } else if ((i) == (7)) {
      return 2402;
    } else if ((i) == (8)) {
      return 2647;
    } else if ((i) == (9)) {
      return 2617;
    } else if ((i) == (10)) {
      return 1481;
    } else if ((i) == (11)) {
      return 648;
    } else if ((i) == (12)) {
      return 2474;
    } else if ((i) == (13)) {
      return 3110;
    } else if ((i) == (14)) {
      return 1227;
    } else {
      return 910;
    }
  }
  public static int ZetasChunk4(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 17;
    } else if ((i) == (1)) {
      return 2761;
    } else if ((i) == (2)) {
      return 583;
    } else if ((i) == (3)) {
      return 2649;
    } else if ((i) == (4)) {
      return 1637;
    } else if ((i) == (5)) {
      return 723;
    } else if ((i) == (6)) {
      return 2288;
    } else if ((i) == (7)) {
      return 1100;
    } else if ((i) == (8)) {
      return 1409;
    } else if ((i) == (9)) {
      return 2662;
    } else if ((i) == (10)) {
      return 3281;
    } else if ((i) == (11)) {
      return 233;
    } else if ((i) == (12)) {
      return 756;
    } else if ((i) == (13)) {
      return 2156;
    } else if ((i) == (14)) {
      return 3015;
    } else {
      return 3050;
    }
  }
  public static int ZetasChunk5(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1703;
    } else if ((i) == (1)) {
      return 1651;
    } else if ((i) == (2)) {
      return 2789;
    } else if ((i) == (3)) {
      return 1789;
    } else if ((i) == (4)) {
      return 1847;
    } else if ((i) == (5)) {
      return 952;
    } else if ((i) == (6)) {
      return 1461;
    } else if ((i) == (7)) {
      return 2687;
    } else if ((i) == (8)) {
      return 939;
    } else if ((i) == (9)) {
      return 2308;
    } else if ((i) == (10)) {
      return 2437;
    } else if ((i) == (11)) {
      return 2388;
    } else if ((i) == (12)) {
      return 733;
    } else if ((i) == (13)) {
      return 2337;
    } else if ((i) == (14)) {
      return 268;
    } else {
      return 641;
    }
  }
  public static int ZetasChunk6(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1584;
    } else if ((i) == (1)) {
      return 2298;
    } else if ((i) == (2)) {
      return 2037;
    } else if ((i) == (3)) {
      return 3220;
    } else if ((i) == (4)) {
      return 375;
    } else if ((i) == (5)) {
      return 2549;
    } else if ((i) == (6)) {
      return 2090;
    } else if ((i) == (7)) {
      return 1645;
    } else if ((i) == (8)) {
      return 1063;
    } else if ((i) == (9)) {
      return 319;
    } else if ((i) == (10)) {
      return 2773;
    } else if ((i) == (11)) {
      return 757;
    } else if ((i) == (12)) {
      return 2099;
    } else if ((i) == (13)) {
      return 561;
    } else if ((i) == (14)) {
      return 2466;
    } else {
      return 2594;
    }
  }
  public static int ZetasChunk7(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 2804;
    } else if ((i) == (1)) {
      return 1092;
    } else if ((i) == (2)) {
      return 403;
    } else if ((i) == (3)) {
      return 1026;
    } else if ((i) == (4)) {
      return 1143;
    } else if ((i) == (5)) {
      return 2150;
    } else if ((i) == (6)) {
      return 2775;
    } else if ((i) == (7)) {
      return 886;
    } else if ((i) == (8)) {
      return 1722;
    } else if ((i) == (9)) {
      return 1212;
    } else if ((i) == (10)) {
      return 1874;
    } else if ((i) == (11)) {
      return 1029;
    } else if ((i) == (12)) {
      return 2110;
    } else if ((i) == (13)) {
      return 2935;
    } else if ((i) == (14)) {
      return 885;
    } else {
      return 2154;
    }
  }
  public static int ZetasValue(int i) {
    if ((i) < (16)) {
      return __default.ZetasChunk0((int) ((i) - (0)));
    } else if ((i) < (32)) {
      return __default.ZetasChunk1((int) ((i) - (16)));
    } else if ((i) < (48)) {
      return __default.ZetasChunk2((int) ((i) - (32)));
    } else if ((i) < (64)) {
      return __default.ZetasChunk3((int) ((i) - (48)));
    } else if ((i) < (80)) {
      return __default.ZetasChunk4((int) ((i) - (64)));
    } else if ((i) < (96)) {
      return __default.ZetasChunk5((int) ((i) - (80)));
    } else if ((i) < (112)) {
      return __default.ZetasChunk6((int) ((i) - (96)));
    } else {
      return __default.ZetasChunk7((int) ((i) - (112)));
    }
  }
  public static int[] NewZetas()
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((128), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 128;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = __default.ZetasValue(_0_i);
      }
    }
    return r;
  }
  public static int GammasChunk0(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 17;
    } else if ((i) == (1)) {
      return 3312;
    } else if ((i) == (2)) {
      return 2761;
    } else if ((i) == (3)) {
      return 568;
    } else if ((i) == (4)) {
      return 583;
    } else if ((i) == (5)) {
      return 2746;
    } else if ((i) == (6)) {
      return 2649;
    } else if ((i) == (7)) {
      return 680;
    } else if ((i) == (8)) {
      return 1637;
    } else if ((i) == (9)) {
      return 1692;
    } else if ((i) == (10)) {
      return 723;
    } else if ((i) == (11)) {
      return 2606;
    } else if ((i) == (12)) {
      return 2288;
    } else if ((i) == (13)) {
      return 1041;
    } else if ((i) == (14)) {
      return 1100;
    } else {
      return 2229;
    }
  }
  public static int GammasChunk1(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1409;
    } else if ((i) == (1)) {
      return 1920;
    } else if ((i) == (2)) {
      return 2662;
    } else if ((i) == (3)) {
      return 667;
    } else if ((i) == (4)) {
      return 3281;
    } else if ((i) == (5)) {
      return 48;
    } else if ((i) == (6)) {
      return 233;
    } else if ((i) == (7)) {
      return 3096;
    } else if ((i) == (8)) {
      return 756;
    } else if ((i) == (9)) {
      return 2573;
    } else if ((i) == (10)) {
      return 2156;
    } else if ((i) == (11)) {
      return 1173;
    } else if ((i) == (12)) {
      return 3015;
    } else if ((i) == (13)) {
      return 314;
    } else if ((i) == (14)) {
      return 3050;
    } else {
      return 279;
    }
  }
  public static int GammasChunk2(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1703;
    } else if ((i) == (1)) {
      return 1626;
    } else if ((i) == (2)) {
      return 1651;
    } else if ((i) == (3)) {
      return 1678;
    } else if ((i) == (4)) {
      return 2789;
    } else if ((i) == (5)) {
      return 540;
    } else if ((i) == (6)) {
      return 1789;
    } else if ((i) == (7)) {
      return 1540;
    } else if ((i) == (8)) {
      return 1847;
    } else if ((i) == (9)) {
      return 1482;
    } else if ((i) == (10)) {
      return 952;
    } else if ((i) == (11)) {
      return 2377;
    } else if ((i) == (12)) {
      return 1461;
    } else if ((i) == (13)) {
      return 1868;
    } else if ((i) == (14)) {
      return 2687;
    } else {
      return 642;
    }
  }
  public static int GammasChunk3(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 939;
    } else if ((i) == (1)) {
      return 2390;
    } else if ((i) == (2)) {
      return 2308;
    } else if ((i) == (3)) {
      return 1021;
    } else if ((i) == (4)) {
      return 2437;
    } else if ((i) == (5)) {
      return 892;
    } else if ((i) == (6)) {
      return 2388;
    } else if ((i) == (7)) {
      return 941;
    } else if ((i) == (8)) {
      return 733;
    } else if ((i) == (9)) {
      return 2596;
    } else if ((i) == (10)) {
      return 2337;
    } else if ((i) == (11)) {
      return 992;
    } else if ((i) == (12)) {
      return 268;
    } else if ((i) == (13)) {
      return 3061;
    } else if ((i) == (14)) {
      return 641;
    } else {
      return 2688;
    }
  }
  public static int GammasChunk4(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1584;
    } else if ((i) == (1)) {
      return 1745;
    } else if ((i) == (2)) {
      return 2298;
    } else if ((i) == (3)) {
      return 1031;
    } else if ((i) == (4)) {
      return 2037;
    } else if ((i) == (5)) {
      return 1292;
    } else if ((i) == (6)) {
      return 3220;
    } else if ((i) == (7)) {
      return 109;
    } else if ((i) == (8)) {
      return 375;
    } else if ((i) == (9)) {
      return 2954;
    } else if ((i) == (10)) {
      return 2549;
    } else if ((i) == (11)) {
      return 780;
    } else if ((i) == (12)) {
      return 2090;
    } else if ((i) == (13)) {
      return 1239;
    } else if ((i) == (14)) {
      return 1645;
    } else {
      return 1684;
    }
  }
  public static int GammasChunk5(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1063;
    } else if ((i) == (1)) {
      return 2266;
    } else if ((i) == (2)) {
      return 319;
    } else if ((i) == (3)) {
      return 3010;
    } else if ((i) == (4)) {
      return 2773;
    } else if ((i) == (5)) {
      return 556;
    } else if ((i) == (6)) {
      return 757;
    } else if ((i) == (7)) {
      return 2572;
    } else if ((i) == (8)) {
      return 2099;
    } else if ((i) == (9)) {
      return 1230;
    } else if ((i) == (10)) {
      return 561;
    } else if ((i) == (11)) {
      return 2768;
    } else if ((i) == (12)) {
      return 2466;
    } else if ((i) == (13)) {
      return 863;
    } else if ((i) == (14)) {
      return 2594;
    } else {
      return 735;
    }
  }
  public static int GammasChunk6(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 2804;
    } else if ((i) == (1)) {
      return 525;
    } else if ((i) == (2)) {
      return 1092;
    } else if ((i) == (3)) {
      return 2237;
    } else if ((i) == (4)) {
      return 403;
    } else if ((i) == (5)) {
      return 2926;
    } else if ((i) == (6)) {
      return 1026;
    } else if ((i) == (7)) {
      return 2303;
    } else if ((i) == (8)) {
      return 1143;
    } else if ((i) == (9)) {
      return 2186;
    } else if ((i) == (10)) {
      return 2150;
    } else if ((i) == (11)) {
      return 1179;
    } else if ((i) == (12)) {
      return 2775;
    } else if ((i) == (13)) {
      return 554;
    } else if ((i) == (14)) {
      return 886;
    } else {
      return 2443;
    }
  }
  public static int GammasChunk7(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 1722;
    } else if ((i) == (1)) {
      return 1607;
    } else if ((i) == (2)) {
      return 1212;
    } else if ((i) == (3)) {
      return 2117;
    } else if ((i) == (4)) {
      return 1874;
    } else if ((i) == (5)) {
      return 1455;
    } else if ((i) == (6)) {
      return 1029;
    } else if ((i) == (7)) {
      return 2300;
    } else if ((i) == (8)) {
      return 2110;
    } else if ((i) == (9)) {
      return 1219;
    } else if ((i) == (10)) {
      return 2935;
    } else if ((i) == (11)) {
      return 394;
    } else if ((i) == (12)) {
      return 885;
    } else if ((i) == (13)) {
      return 2444;
    } else if ((i) == (14)) {
      return 2154;
    } else {
      return 1175;
    }
  }
  public static int GammasValue(int i) {
    if ((i) < (16)) {
      return __default.GammasChunk0((int) ((i) - (0)));
    } else if ((i) < (32)) {
      return __default.GammasChunk1((int) ((i) - (16)));
    } else if ((i) < (48)) {
      return __default.GammasChunk2((int) ((i) - (32)));
    } else if ((i) < (64)) {
      return __default.GammasChunk3((int) ((i) - (48)));
    } else if ((i) < (80)) {
      return __default.GammasChunk4((int) ((i) - (64)));
    } else if ((i) < (96)) {
      return __default.GammasChunk5((int) ((i) - (80)));
    } else if ((i) < (112)) {
      return __default.GammasChunk6((int) ((i) - (96)));
    } else {
      return __default.GammasChunk7((int) ((i) - (112)));
    }
  }
  public static int[] NewGammas()
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((128), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 128;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = __default.GammasValue(_0_i);
      }
    }
    return r;
  }
  public static int[] Add(int[] f, int[] g)
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 256;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        int _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Add((f)[(_0_i)], (g)[(_0_i)]);
        (r)[dafny.Helpers.toInt((_0_i))] = _out0;
      }
    }
    return r;
  }
  public static int[] Sub(int[] f, int[] g)
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 256;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        int _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Sub((f)[(_0_i)], (g)[(_0_i)]);
        (r)[dafny.Helpers.toInt((_0_i))] = _out0;
      }
    }
    return r;
  }
  public static int[] Copy(int[] f)
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 256;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = (f)[(_0_i)];
      }
    }
    return r;
  }
  public static void ForwardStage(int[] f, int[] r, int[] roots, int s)
  {
    int _0_l;
    _0_l = __default.Len(s);
    int _1_blocks;
    _1_blocks = dafny.DafnyEuclidean.EuclideanDivision(128, _0_l);
    int _hi0 = _1_blocks;
    for (int _2_block = 0; _2_block < _hi0; _2_block++) {
      int _3_start;
      _3_start = (int) (((int) ((2) * (_0_l))) * (_2_block));
      int _4_k;
      _4_k = (int) ((dafny.DafnyEuclidean.EuclideanDivision(128, _0_l)) + (_2_block));
      int _5_z;
      _5_z = (roots)[(_4_k)];
      int _hi1 = _0_l;
      for (int _6_offset = 0; _6_offset < _hi1; _6_offset++) {
        int _7_i;
        _7_i = (int) ((_3_start) + (_6_offset));
        int _8_t;
        int _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Mul(_5_z, (f)[((int) ((_7_i) + (_0_l)))]);
        _8_t = _out0;
        int _out1;
        _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Add((f)[(_7_i)], _8_t);
        (r)[dafny.Helpers.toInt((_7_i))] = _out1;
        int _index0 = (int) ((_7_i) + (_0_l));
        int _out2;
        _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Sub((f)[(_7_i)], _8_t);
        (r)[dafny.Helpers.toInt(_index0)] = _out2;
      }
    }
  }
  public static void InverseStage(int[] f, int[] r, int[] roots, int s)
  {
    int _0_l;
    _0_l = __default.Len((int) ((6) - (s)));
    int _1_blocks;
    _1_blocks = dafny.DafnyEuclidean.EuclideanDivision(128, _0_l);
    int _hi0 = _1_blocks;
    for (int _2_block = 0; _2_block < _hi0; _2_block++) {
      int _3_start;
      _3_start = (int) (((int) ((2) * (_0_l))) * (_2_block));
      int _4_k;
      _4_k = (int) (((int) ((dafny.DafnyEuclidean.EuclideanDivision(256, _0_l)) - (1))) - (_2_block));
      int _5_z;
      _5_z = (roots)[(_4_k)];
      int _hi1 = _0_l;
      for (int _6_offset = 0; _6_offset < _hi1; _6_offset++) {
        int _7_i;
        _7_i = (int) ((_3_start) + (_6_offset));
        int _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Add((f)[(_7_i)], (f)[((int) ((_7_i) + (_0_l)))]);
        (r)[dafny.Helpers.toInt((_7_i))] = _out0;
        int _index0 = (int) ((_7_i) + (_0_l));
        int _out1;
        _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.MulSub(_5_z, (f)[((int) ((_7_i) + (_0_l)))], (f)[(_7_i)]);
        (r)[dafny.Helpers.toInt(_index0)] = _out1;
      }
    }
  }
  public static void Scale(int[] a, int scalar)
  {
    int _hi0 = 256;
    for (int _0_i = 0; _0_i < _hi0; _0_i++) {
      int _out0;
      _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Mul((a)[(_0_i)], scalar);
      (a)[dafny.Helpers.toInt((_0_i))] = _out0;
    }
  }
  public static int[] Ntt(int[] f)
  {
    int[] r = new int[0];
    if(true) {
      int[] _out0;
      _out0 = __default.Copy(f);
      r = _out0;
      int[] _0_scratch;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_scratch = _nw0;
      int[] _1_roots;
      int[] _out1;
      _out1 = __default.NewZetas();
      _1_roots = _out1;
      int _hi0 = 7;
      for (int _2_s = 0; _2_s < _hi0; _2_s++) {
        __default.ForwardStage(r, _0_scratch, _1_roots, _2_s);
        int[] _rhs0 = _0_scratch;
        int[] _rhs1 = r;
        r = _rhs0;
        _0_scratch = _rhs1;
      }
      __default.Wipe(_0_scratch);
    }
    return r;
  }
  public static int[] InverseNtt(int[] f)
  {
    int[] r = new int[0];
    if(true) {
      int[] _out0;
      _out0 = __default.Copy(f);
      r = _out0;
      int[] _0_scratch;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_scratch = _nw0;
      int[] _1_roots;
      int[] _out1;
      _out1 = __default.NewZetas();
      _1_roots = _out1;
      int _hi0 = 7;
      for (int _2_s = 0; _2_s < _hi0; _2_s++) {
        __default.InverseStage(r, _0_scratch, _1_roots, _2_s);
        int[] _rhs0 = _0_scratch;
        int[] _rhs1 = r;
        r = _rhs0;
        _0_scratch = _rhs1;
      }
      __default.Wipe(_0_scratch);
      __default.Scale(r, 3303);
    }
    return r;
  }
  public static void BaseCase(int a0, int a1, int b0, int b1, int gamma, int[] r, int i)
  {
    int _0_t;
    int _out0;
    _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.Mul(a1, b1);
    _0_t = _out0;
    int _1_c0;
    int _out1;
    _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.AddMul(a0, b0, _0_t, gamma);
    _1_c0 = _out1;
    int _2_c1;
    int _out2;
    _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.AddMul(a0, b1, a1, b0);
    _2_c1 = _out2;
    int _index0 = (int) ((i) + (1));
    int _rhs0 = _1_c0;
    int _rhs1 = _2_c1;
    int[] _lhs0 = r;
    int _lhs1 = i;
    int[] _lhs2 = r;
    int _lhs3 = (int) ((i) + (1));
    _lhs0[dafny.Helpers.toInt(_lhs1)] = _rhs0;
    _lhs2[dafny.Helpers.toInt(_lhs3)] = _rhs1;
  }
  public static int[] NttMul(int[] f, int[] g)
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int[] _0_gammas;
      int[] _out0;
      _out0 = __default.NewGammas();
      _0_gammas = _out0;
      int _hi0 = 128;
      for (int _1_i = 0; _1_i < _hi0; _1_i++) {
        __default.BaseCase((f)[((int) ((2) * (_1_i)))], (f)[((int) (((int) ((2) * (_1_i))) + (1)))], (g)[((int) ((2) * (_1_i)))], (g)[((int) (((int) ((2) * (_1_i))) + (1)))], (_0_gammas)[(_1_i)], r, (int) ((2) * (_1_i)));
      }
    }
    return r;
  }
  public static void Wipe(int[] a)
  {
    int _0_length;
    _0_length = (a).length;
    int _hi0 = _0_length;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (a)[dafny.Helpers.toInt((_1_i))] = 0;
    }
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial._default";
  }
}
