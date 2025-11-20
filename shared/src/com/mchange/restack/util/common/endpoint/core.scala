package com.mchange.restack.util.common.endpoint

import sttp.tapir.Schema
import com.mchange.restack.util.common.{Jwk,Jwks,Protocol}

given Schema[Protocol] = Schema.derived

given Schema[Jwk]  = Schema.derived
given Schema[Jwks] = Schema.derived

