package com.shop.db

fun connect(): Pool.Conn = Pool.open()

val limit = 50

class Cursor
