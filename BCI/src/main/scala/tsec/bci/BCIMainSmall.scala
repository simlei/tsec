package tsec.bci

import cats.Id
import cats.effect._
import tsec.cipher.symmetric.jca.{AES128GCM, CBC, DES, IvProcess, JCAIvGen, SecretKey}
import tsec.cipher.common.padding.{PKCS7Padding, SymmetricPadding}
import tsec.cipher.symmetric.{AAD, BlockCipher, CipherMode, CipherText, Encryptor, Iv, PlainText}
import tsec.cipher.symmetric.jca.primitive.JCAPrimitiveCipher
import tsec.common._
import cats.data.Validated
import scopt.OParser
import tsec.bci.BCIMainSmall.TreeApiTest.{testInputDecrTreeApi, testInputTreeApi, testOutputDecrTreeApi, testOutputTreeApi}
import tsec.bci.DESCfg.CmdlineApi_NoGen
import java.io.File
import scala.util.Try


object BCIMainSmall {


  // bcitool DES --op encrypt --padding PCKS5 --iv-string "IV HELLO!" --key-string "SECRET"
  // bcitool DES --op decrypt --padding PCKS5 --iv-string "IV HELLO!" --key-string "SECRET"
  object CmdlineApi {

    import java.math.BigInteger
    //  modes: CBC, CFB, CTR, ECB, OFB, OFBx
//    encrypt: DESCfg.EncryptionCfg = DESCfg.templateEncryption(),
//    decrypt: DESCfg.DecryptionCfg = DESCfg.templateDecryption()
    // bcitool DES --op encrypt --iv-text helloworldIV --key-hex 3ab7 -m CBC -p PKCS5



  }

  object TreeApiTest {

    var outputStore: Array[Byte] = null

    def testInputTreeApi(): PlainText = {
      PlainText("Hello config world!".utf8Bytes)
    }

    def testOutputTreeApi(out: CipherText[DES]): Unit = {
      outputStore = out.toConcatenated
    }

    def testInputDecrTreeApi(): CipherText[DES] = {
      return DESCfg.ciphertextFromBytes(outputStore)
    }

    def testOutputDecrTreeApi(in: PlainText): Unit = {
      println("Round Trip with Cfg: " + in.toUtf8String)
    }

    def testTreeApiRun() = {
      val encrIO = DESCfg.templateEncryption()
      val decrIO = DESCfg.templateDecryption()
      val customEnc = encrIO.copy(input = testInputTreeApi, output = testOutputTreeApi)
      val customDec = decrIO.copy(input = testInputDecrTreeApi, output = testOutputDecrTreeApi)
      DESCfg.encrypt(customEnc)
      DESCfg.decrypt(customDec)
    }
  }

  def main(args: Array[String]): Unit = {

//    println("Implicit: " + endecImplicitTest())
//    println("Explicit: " + endecExplicitTest())
//    testEncryptor1()


    TreeApiTest.testTreeApiRun()

    val iv = Iv[DES]("Hellowor".getBytes)
    val desKey1 = DES.buildKey[Id]("12345678".getBytes())

    println("Key:" + toHexString(desKey1.getEncoded))
    val desKey2 = DES.generateKey[Id]
    println("Key2:" + toHexString(desKey2.getEncoded))
    testEncryptor2(
      iv,
      desKey1
    )
    testEncryptor2(
        iv,
        desKey2
      )
  }

  val toEncrypt = "------------HI---------".utf8Bytes

  def toHexString(s: Array[Byte]) : String = {
    s.map((b: Byte) => (b+128).toHexString).mkString(",")
  }

  import tsec.bci.DESCfg
  def testEncryptor2(desIv: Iv[DES], desKey: SecretKey[DES]): Unit = {

    //    val desIv: Iv[DES] = JCAIvGen.random[IO, DES].genIv.unsafeRunSync()
    val desCipher: BlockCipher[DES] = implicitly
    val desMode: CipherMode[CBC] = implicitly
    val desPadding: SymmetricPadding[PKCS7Padding] = implicitly
    val desIvProcess = implicitly[IvProcess[DES,CBC,PKCS7Padding]]

    val desEncryptor : Encryptor[IO, DES, SecretKey] = DESCfg.createEncryptor(desIv, desIvProcess, desCipher, desMode, desPadding)
    val result: CipherText[DES] =  desEncryptor.encrypt(PlainText(toEncrypt), desKey, desIv).unsafeRunSync()
    val resultAsHexString = toHexString(result.toConcatenated)
    println("encryptored DES: " + resultAsHexString)

    val resultBack: PlainText = desEncryptor.decrypt(result, desKey).unsafeRunSync()
    val resultBackAsHexString = toHexString(resultBack.toArray)
    val resultBackAsString = resultBack.toUtf8String
    println("decryptored DES: " + resultBackAsHexString)
    println("decryptored DES: " + resultBackAsString)
  }

  def testEncryptor1(): Unit = {
    val desKey: SecretKey[DES] = DES.generateKey[Id]
    val desIv: Iv[DES] = JCAIvGen.random[IO, DES].genIv.unsafeRunSync()
//    val desIv: Iv[DES] = JCAIvGen.random[IO, DES].genIv.unsafeRunSync()
    val desCipher: BlockCipher[DES] = implicitly
    val desMode: CipherMode[CBC] = implicitly
    val desPadding: SymmetricPadding[PKCS7Padding] = implicitly
    val desIvProcess = implicitly[IvProcess[DES,CBC,PKCS7Padding]]

    val desEncryptor : Encryptor[IO, DES, SecretKey] = DESCfg.createEncryptor(desIv, desIvProcess, desCipher, desMode, desPadding)
    val result: CipherText[DES] =  desEncryptor.encrypt(PlainText(toEncrypt), desKey, desIv).unsafeRunSync()
    val resultAsHexString = toHexString(result.toConcatenated)
    println("encryptored DES: " + resultAsHexString)

    val resultBack: PlainText = desEncryptor.decrypt(result, desKey).unsafeRunSync()
    val resultBackAsHexString = toHexString(resultBack.toArray)
    val resultBackAsString = resultBack.toUtf8String
    println("decryptored DES: " + resultBackAsHexString)
    println("decryptored DES: " + resultBackAsString)
  }


  def endecImplicitTest(): String = {
    val bla = implicitly[Sync[IO]]
    val desKey: SecretKey[DES] = DES.generateKey[Id]
    val desIv: Iv[DES] = JCAIvGen.random[IO, DES].genIv.unsafeRunSync()
    val output = endecImplicit[DES, CBC, PKCS7Padding](desKey, desIv)(toEncrypt.toUtf8String)
    return output
  }
  def endecExplicitTest(): String = {

    val desKey: SecretKey[DES] = DES.generateKey[Id]
    val desIv: Iv[DES] = JCAIvGen.random[IO, DES].genIv.unsafeRunSync()
    val desCipher: BlockCipher[DES] = implicitly
    val desMode: CipherMode[CBC] = implicitly
    val desPadding: SymmetricPadding[PKCS7Padding] = implicitly
    val desIvProcess = implicitly[IvProcess[DES,CBC,PKCS7Padding]]

    val output = endecExplicit[DES,CBC,PKCS7Padding](desKey, desIv, desIvProcess, desCipher, desMode, desPadding)(toEncrypt.toUtf8String)
    return output
  }

  def endecExplicit[A,M,P]
  ( secretKey: SecretKey[A],
    iv: Iv[A],
    ivProcess: IvProcess[A, M, P],
    blockCipher: BlockCipher[A],
    cipherMode: CipherMode[M],
    padding: SymmetricPadding[P]
  )
  (plainText: String) : String = {
    val SYNC = implicitly[Sync[IO]]
    val instance = JCAPrimitiveCipher.sync[IO, A, M, P](
      blockCipher,
      cipherMode,
      padding,
      SYNC,
      ivProcess,
    )
    val plain = PlainText(plainText.getBytes)
    val encrypted : CipherText[A] = instance.encrypt(plain, secretKey, iv).unsafeRunSync()
    val decrypted : PlainText = instance.decrypt(encrypted, secretKey).unsafeRunSync()
    return decrypted.toUtf8String
  }

  def endecImplicit[A: BlockCipher, M: CipherMode, P: SymmetricPadding]
  ( secretKey: SecretKey[A],
    iv: Iv[A]
  )(
    plainText: String
  )( implicit
    F: Sync[IO],
    ivProcess: IvProcess[A, M, P]
  ) : String = {
    implicit val instance = JCAPrimitiveCipher.sync[IO, A, M, P]
    val plain = PlainText(plainText.getBytes)
    val result = for {
      key <- IO.pure(secretKey)
      iv <- IO.pure(iv)
      encrypted <- instance.encrypt(plain, key, iv)
      decrypted <- instance.decrypt(encrypted, key)
    } yield decrypted.toUtf8String
    return result.unsafeRunSync()
  }

 def AADExample(): Unit = {
   implicit val gcmstrategy        = AES128GCM.defaultIvStrategy[IO]
   implicit val cachedAADEncryptor = AES128GCM.genEncryptor[IO]
   val aad = AAD("myAdditionalAuthenticationData".utf8Bytes)
   val encryptAAD: IO[String] =
     for {
       key       <- AES128GCM.generateKey[IO]                                    //Generate our key
       encrypted <- AES128GCM.encryptWithAAD[IO](PlainText(toEncrypt), key, aad) //Encrypt
       decrypted <- AES128GCM.decryptWithAAD[IO](encrypted, key, aad)            //Decrypt
     } yield decrypted.toUtf8String // "hi hello welcome to tsec!"
 }

}
