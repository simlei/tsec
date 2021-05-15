package tsec.simleidev

import cats.Id
import cats.effect._
import tsec.cipher.symmetric.jca.{AES128GCM, CBC, DES, IvProcess, JCAIvGen, SecretKey}
import tsec.cipher.common.padding.{PKCS7Padding, SymmetricPadding}
import tsec.cipher.symmetric.{AAD, BlockCipher, CipherMode, CipherText, Encryptor, Iv, PlainText}
import tsec.cipher.symmetric.jca.primitive.JCAPrimitiveCipher
import tsec.common._
import cats.data.Validated
import scopt.OParser
import java.io.File
import scala.util.Try

object SimleiDev {

  val toEncrypt = "TESTTEXT".utf8Bytes

  def main(args: Array[String]): Unit = {
    val iv = Iv[DES]("Hellowor".getBytes)
    val desKey1 = DES.buildKey[Id]("12345678".getBytes())
    println("Key:" + toHexString(desKey1.getEncoded))
    val desKey2 = DES.generateKey[Id]
    println("Key2:" + toHexString(desKey2.getEncoded))
    // keys just for example, how to create...
    println ( endecImplicitTest() )
    println ( endecExplicitTest() )
  }

  def toHexString(s: Array[Byte]): String = {
    s.map((b: Byte) => (b + 128).toHexString).mkString(",")
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
    val desIvProcess = implicitly[IvProcess[DES, CBC, PKCS7Padding]]

    val output = endecExplicit[DES, CBC, PKCS7Padding](desKey, desIv, desIvProcess, desCipher, desMode, desPadding)(toEncrypt.toUtf8String)
    return output
  }

  def endecExplicit[A, M, P]
  (secretKey: SecretKey[A],
   iv: Iv[A],
   ivProcess: IvProcess[A, M, P],
   blockCipher: BlockCipher[A],
   cipherMode: CipherMode[M],
   padding: SymmetricPadding[P]
  )
  (plainText: String): String = {
    val SYNC = implicitly[Sync[IO]]
    val instance = JCAPrimitiveCipher.sync[IO, A, M, P](
      blockCipher,
      cipherMode,
      padding,
      SYNC,
      ivProcess,
    )
    val plain = PlainText(plainText.getBytes)
    val encrypted: CipherText[A] = instance.encrypt(plain, secretKey, iv).unsafeRunSync()
    val decrypted: PlainText = instance.decrypt(encrypted, secretKey).unsafeRunSync()
    return decrypted.toUtf8String
  }

  def endecImplicit[A: BlockCipher, M: CipherMode, P: SymmetricPadding]
  (secretKey: SecretKey[A],
   iv: Iv[A]
  )(
    plainText: String
  )(implicit
    F: Sync[IO],
    ivProcess: IvProcess[A, M, P]
  ): String = {
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
    implicit val gcmstrategy = AES128GCM.defaultIvStrategy[IO]
    implicit val cachedAADEncryptor = AES128GCM.genEncryptor[IO]
    val aad = AAD("myAdditionalAuthenticationData".utf8Bytes)
    val encryptAAD: IO[String] =
      for {
        key <- AES128GCM.generateKey[IO] //Generate our key
        encrypted <- AES128GCM.encryptWithAAD[IO](PlainText(toEncrypt), key, aad) //Encrypt
        decrypted <- AES128GCM.decryptWithAAD[IO](encrypted, key, aad) //Decrypt
      } yield decrypted.toUtf8String // "hi hello welcome to tsec!"
  }

}
