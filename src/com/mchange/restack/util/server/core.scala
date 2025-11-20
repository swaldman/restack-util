package com.mchange.restack.util.server

import com.mchange.restack.util.common.{Jwk,Service}
import com.mchange.restack.util.server.crypto.BouncyCastleSecp256r1

import java.security.interfaces.ECPublicKey

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

