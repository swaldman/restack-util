package com.mchange.restack.util.common.endpoint

import sttp.tapir.Schema
import com.mchange.restack.util.common.Protocol

given Schema[Protocol] = Schema.derived

