package tsec.bci

import cats.effect.Sync
import tsec.cipher.symmetric

object BCIMain {

  /** These are the imports you will need for basic usage */

  import cats.effect.IO
  import tsec.cipher.symmetric._
  import tsec.cipher.symmetric.jca._
  import tsec.common._

  //Feel free to choose any of the default Cipher constructions.
  //For non-authenticated ciphers, we recommend AES-CTR

  val toEncrypt = "hi hello welcome to tsec".utf8Bytes

  implicit val ctrStrategy: IvGen[IO, AES128CTR] = AES128CTR.defaultIvStrategy[IO]
  implicit val cachedInstance = AES128CTR.genEncryptor[IO] //Cache the implicit

  val onlyEncrypt: IO[String] =
    for {
      key <- AES128CTR.generateKey[IO] //Generate our key
      encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
      decrypted <- AES128CTR.decrypt[IO](encrypted, key)
    } yield decrypted.toUtf8String // "hi hello welcome to tsec!"

  /** You can also turn it into a singular array with the IV concatenated at the end */
  val onlyEncrypt2: IO[String] =
    for {
      key <- AES128CTR.generateKey[IO] //Generate our key
      encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
      array = encrypted.toConcatenated
      from <- IO.fromEither(AES128CTR.ciphertextFromConcat(array))
      decrypted <- AES128CTR.decrypt[IO](from, key)
    } yield decrypted.toUtf8String // "hi hello welcome to tsec!"

  /** An authenticated encryption and decryption */
  implicit val gcmstrategy = AES128GCM.defaultIvStrategy[IO]
  implicit val cachedAADEncryptor = AES128GCM.genEncryptor[IO]

  val aad = AAD("myAdditionalAuthenticationData".utf8Bytes)
  val encryptAAD: IO[String] =
    for {
      key <- AES128GCM.generateKey[IO] //Generate our key
      encrypted <- AES128GCM.encryptWithAAD[IO](PlainText(toEncrypt), key, aad) //Encrypt
      decrypted <- AES128GCM.decryptWithAAD[IO](encrypted, key, aad) //Decrypt
    } yield decrypted.toUtf8String // "hi hello welcome to tsec!"

  /** For more advanced usage, i.e you know which cipher you want specifically, you must import padding
    * as well as the low level package
    *
    * this is not recommended, but useful for.. science!
    *
    */

  import tsec.cipher.common.padding._
  import tsec.cipher.symmetric.jca.primitive._

  val desStrategy = JCAIvGen.random[IO, DES]
  implicit val instance = JCAPrimitiveCipher.sync[IO, DES, CBC, PKCS7Padding]

  val advancedUsage: IO[String] = for {
    key <- DES.generateKey[IO]
    iv <- desStrategy.genIv
    encrypted <- instance.encrypt(PlainText(toEncrypt), key, iv) //Encrypt our message, with our auth data
    decrypted <- instance.decrypt(encrypted, key) //Decrypt our message: We need to pass it the same AAD
  } yield decrypted.toUtf8String


  def printOutput(label: String, content: Any): Unit = {
    println(s"$label: `" + content + "`")
  }

  import scala.reflect._
  var modeTag = classTag[CBC]

  def main(args: Array[String]): Unit = {
//    printOutput("DES EnDec", endecWith(modeTag).unsafeRunSync())
  }

//  def endecWith[C, M, P](
//               implicit algoTag: BlockCipher[C],
//               modeSpec: CipherMode[M],
//               paddingTag: SymmetricPadding[P],
//               ivProcess: IvProcess[C, M, P]
//             ) : IO[String] = {
//    val cipher = JCAPrimitiveCipher.sync[IO,C,M,P]
//    return for {
//      key <- DES.generateKey[IO]
//      iv <- ivProcess
//      encrypted <- cipher.encrypt(PlainText(toEncrypt), key, iv)
//      decrypted <- cipher.decrypt(encrypted, key)
//    } yield decrypted.toUtf8String
//  }

  //    val desIV = desStrategy.genIv
  //    val desKey = DES.generateKey[IO]
  //    type Cipher = DES;
  //    type Padding = PKCS7Padding;
}
