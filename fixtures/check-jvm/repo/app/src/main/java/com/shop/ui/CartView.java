package com.shop.ui;

// import com.shop.db.Row;
import com.shop.db.Pool;
import com.shop.db.Pool.Conn;
import static com.shop.db.Pool.open;
import com.shop.db.gen.Rows;
import com.shop.db.hand.*;
import com.shop.util.Strings;
import java.util.List;
import com.shop.db.Missing;

/* import com.shop.db.Row; */
public class CartView {
    static final String SQL = """
        import com.shop.db.Cursor;
        """;
    String text = "import com.shop.db.Row;";
}
