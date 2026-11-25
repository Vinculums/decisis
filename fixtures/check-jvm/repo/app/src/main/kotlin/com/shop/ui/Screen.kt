package com.shop.ui

import com.shop.db.Pool as ConnectionPool
import com.shop.db.connect
import com.shop.db.limit
import com.shop.db.Cursor
import com.shop.db.QueriesKt
import com.shop.util.Strings
import kotlin.collections.List

val note = """
import com.shop.db.Row
"""
val label = "${"import com.shop.db.Row"}"
