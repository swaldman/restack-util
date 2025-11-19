package com.mchange.restack.util.server.exception

class RestackUtilServerException( message : String, cause : Throwable = null ) extends Exception( message, cause )

class BadLocation( message : String, cause : Throwable = null ) extends RestackUtilServerException( message, cause )
class BadIdentifierFormat( message : String, cause : Throwable = null ) extends RestackUtilServerException( message, cause )
class BadServiceUrl( message : String, cause : Throwable = null ) extends RestackUtilServerException( message, cause )
class UnknownAlgorithmOrCurve( message : String, cause : Throwable = null ) extends RestackUtilServerException( message, cause )
class UnsupportedProtocol( message : String, cause : Throwable = null ) extends RestackUtilServerException( message, cause )
