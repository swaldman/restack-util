package com.mchange.restack.util.common

import com.github.plokhotnyuk.jsoniter_scala.core.*
import com.github.plokhotnyuk.jsoniter_scala.macros.*

enum Service:
  case protopost, seismic;

enum Protocol( val defaultPort : Int ):
  case http  extends Protocol(80)  // for testing only! auth credentials are sent "in the clear", so only https should be used in production
  case https extends Protocol(443)

object Jwk:
  given JsonValueCodec[Jwk] = JsonCodecMaker.make
  val DefaultKty = "EC"
  val DefaultCrv = "P-256"
  val DefaultAlg = "ES256"
  val DefaultUse = "sig"
case class Jwk( x : String, y : String, kid : String, kty : String, crv : String, alg : String, use : String )

object Jwks:
  given JsonValueCodec[Jwks] = JsonCodecMaker.make
case class Jwks( keys : List[Jwk] )

