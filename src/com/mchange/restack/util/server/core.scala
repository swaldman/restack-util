package com.mchange.restack.util.server

import com.mchange.restack.util.common.{Jwk,Service}
import com.mchange.restack.util.server.crypto.{*,given}
import com.mchange.restack.util.server.exception.*

import com.mchange.cryptoutil.{*,given}

import java.security.interfaces.ECPublicKey
import java.security.interfaces.ECPrivateKey
import java.util.Base64

import scala.collection.immutable

import com.github.plokhotnyuk.jsoniter_scala.core.*
import com.github.plokhotnyuk.jsoniter_scala.macros.*

import sttp.tapir.Schema

def createJwk( publicKey : ECPublicKey, service : Service ) : Jwk =
  Jwk(
    x = BouncyCastleSecp256r1.fieldValueToBase64Url( publicKey.getW().getAffineX() ),
    y = BouncyCastleSecp256r1.fieldValueToBase64Url( publicKey.getW().getAffineY() ),
    kid = service.toString,
    kty = Jwk.DefaultKty,
    crv = Jwk.DefaultCrv,
    alg = Jwk.DefaultAlg,
    use = Jwk.DefaultUse
  )

class JwkProviders:
  import scala.collection.mutable
  import com.auth0.jwk.{Jwk,JwkProvider,JwkProviderBuilder}
  import com.mchange.restack.util.common.Service
  import com.mchange.restack.util.server.identity.Location

  private val innerMap : mutable.Map[Location.Simple,JwkProvider] = mutable.HashMap.empty[Location.Simple,JwkProvider]
  private def get( location : Location.Simple ) : JwkProvider = this.synchronized:
    innerMap.getOrElseUpdate( location, new JwkProviderBuilder(location.toUrl).build() )
  def get( location : Location.Simple, service : Service ) : Option[Jwk] =
    Option( this.get( location ).get( service.toString ) )

object Envelope:
  given JsonValueCodec[Envelope] = JsonCodecMaker.make
  given Schema[Envelope]         = Schema.derived
  def apply( messageBytes : Array[Byte], privateKey : ECPrivateKey ) : Envelope =
    val signature = BouncyCastleSecp256r1.sign( messageBytes, privateKey )
    val signer = BouncyCastleSecp256r1.publicKeyToUncompressedFormatBytes(BouncyCastleSecp256r1.publicKeyFromPrivate(privateKey))
    Envelope( messageBytes.base64url, signature.unsafeInternalArray.base64url, signer.base64url )
  def wrap[T : JsonValueCodec]( messageThang : T, privateKey : ECPrivateKey ) : Envelope = this.apply( writeToArray(messageThang), privateKey )
  def verifyUnwrap[T : JsonValueCodec]( envelope : Envelope ) : T =
    val messageBytes = envelope.message.toArray  // XXX: should I use unsafeArray?
    if BouncyCastleSecp256r1.verify( messageBytes, envelope.signature, envelope.signer ) then
      readFromArray[T]( messageBytes )
    else
      throw new SignatureDoesNotVerify( s"The signature of " + envelope + " does not verify." )

case class Envelope( messageBase64url : String, signatureBase64url : String, signerBase64url : String ):
  lazy val message : immutable.ArraySeq[Byte] = immutable.ArraySeq.ofByte( Base64.getUrlDecoder().decode( messageBase64url ) )
  lazy val signature : SignatureSHA256withECDSA = SignatureSHA256withECDSA( Base64.getUrlDecoder().decode( signatureBase64url ) )
  lazy val signer : ECPublicKey = BouncyCastleSecp256r1.publicKeyFromUncompressedFormatBytes( Base64.getUrlDecoder().decode( signerBase64url ) )
  lazy val hash : Hash.SHA3_256 = Hash.SHA3_256.hash( message.toArray ++ signature.unsafeInternalArray ++ BouncyCastleSecp256r1.publicKeyToUncompressedFormatBytes(signer) )
  override def toString = s"Envelope[${hash.hex0x}]"

