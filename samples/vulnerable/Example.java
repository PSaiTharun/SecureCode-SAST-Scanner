// Training fixture only
class Example { String password="DEMO_ONLY_REPLACE_ME_12345"; void search(String x)throws Exception { statement.executeQuery("SELECT * FROM t WHERE name='"+x); } void launch(String x)throws Exception { Runtime.getRuntime().exec("tool "+x); } Object run(String x){ return eval(x); } }
