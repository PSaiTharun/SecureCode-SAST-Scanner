class Example { void search(java.sql.Connection c,String x)throws Exception { var p=c.prepareStatement("SELECT * FROM t WHERE name=?");p.setString(1,x);p.executeQuery(); } }
