/*
 * Copyright (c) 2004, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package software.aws.rds.jdbc.postgresql.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertThrows;

import software.aws.rds.jdbc.postgresql.Driver;

import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.postgresql.PGProperty;
import org.postgresql.test.TestUtil;
import org.postgresql.util.LogWriterHandler;
import org.postgresql.util.NullOutputStream;
import org.postgresql.util.URLCoder;

import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Properties;
import java.util.logging.Handler;
import java.util.logging.Logger;

/*
 * Tests the dynamically created class software.aws.rds.jdbc.postgresql.Driver
 *
 */
public class AwsDriverTest {

  @Before
  public void setUp() throws SQLException {
    if (!software.aws.rds.jdbc.postgresql.Driver.isRegistered()) {
      software.aws.rds.jdbc.postgresql.Driver.register();
    }

    if (org.postgresql.Driver.isRegistered()) {
      org.postgresql.Driver.deregister();
    }
  }

  @AfterAll
  static void afterAll() throws SQLException {
    if (!org.postgresql.Driver.isRegistered()) {
      org.postgresql.Driver.register();
    }
  }

  @Test
  public void urlIsNotForPostgreSQL() throws SQLException {
    Driver driver = new Driver();

    assertNull(driver.connect("jdbc:otherdb:database", new Properties()));
  }

  /**
   * According to the javadoc of java.sql.Driver.connect(...), calling abort when the {@code executor} is {@code null}
   * results in SQLException
   */
  @Test
  public void urlIsNull() {
    Driver driver = new Driver();

    assertThrows(SQLException.class, () -> driver.connect(null, new Properties()));
  }

  @Test
  public void testAcceptAwsProtocolOnly() throws Exception {
    Driver drv = new Driver();
    assertNotNull(drv);

    verifyUrl(drv, "jdbc:postgresql:aws://localhost/test", "localhost", "5432", "test");
    assertFalse(drv.acceptsURL("jdbc:postgresql://localhost:5432/test"));
  }

  /*
   * This tests the acceptsURL() method with a couple of well and poorly formed jdbc urls.
   */
  @Test
  public void testAcceptsURLAws() throws Exception {
    // Load the driver (note clients should never do it this way!)
    Driver drv = new Driver();
    assertNotNull(drv);

    // These are always correct

    verifyUrl(drv, "jdbc:postgresql:aws:test", "localhost", "5432", "test");
    verifyUrl(drv, "jdbc:postgresql:aws://localhost/test", "localhost", "5432", "test");
    verifyUrl(drv, "jdbc:postgresql:aws://localhost:5432/test", "localhost", "5432", "test");
    verifyUrl(drv, "jdbc:postgresql:aws://127.0.0.1/anydbname", "127.0.0.1", "5432", "anydbname");
    verifyUrl(drv, "jdbc:postgresql:aws://127.0.0.1:5433/hidden", "127.0.0.1", "5433", "hidden");
    verifyUrl(drv, "jdbc:postgresql:aws://[::1]:5740/db", "[::1]", "5740", "db");

    // Badly formatted url's
    assertFalse(drv.acceptsURL("jdbc:postgres:aws:test"));
    assertFalse(drv.acceptsURL("postgresql:aws:test"));
    assertFalse(drv.acceptsURL("db"));
    assertFalse(drv.acceptsURL("jdbc:postgresql:aws://localhost:5432a/test"));
    assertFalse(drv.acceptsURL("jdbc:postgresql:aws://localhost:500000/test"));
    assertFalse(drv.acceptsURL("jdbc:postgresql:aws://localhost:0/test"));
    assertFalse(drv.acceptsURL("jdbc:postgresql:aws://localhost:-2/test"));

    // failover urls
    verifyUrl(drv, "jdbc:postgresql:aws://localhost,127.0.0.1:5432/test", "localhost,127.0.0.1",
            "5432,5432", "test");
    verifyUrl(drv, "jdbc:postgresql:aws://localhost:5433,127.0.0.1:5432/test", "localhost,127.0.0.1",
            "5433,5432", "test");
    verifyUrl(drv, "jdbc:postgresql:aws://[::1],[::1]:5432/db", "[::1],[::1]", "5432,5432", "db");
    verifyUrl(drv, "jdbc:postgresql:aws://[::1]:5740,127.0.0.1:5432/db", "[::1],127.0.0.1", "5740,5432",
            "db");
  }

  private void verifyUrl(Driver drv, String url, String hosts, String ports, String dbName)
      throws Exception {
    assertTrue(url, drv.acceptsURL(url));
    Method parseMethod =
        drv.getClass().getDeclaredMethod("parseURL", String.class, Properties.class);
    parseMethod.setAccessible(true);
    Properties p = (Properties) parseMethod.invoke(drv, url, null);
    assertEquals(url, dbName, p.getProperty(PGProperty.PG_DBNAME.getName()));
    assertEquals(url, hosts, p.getProperty(PGProperty.PG_HOST.getName()));
    assertEquals(url, ports, p.getProperty(PGProperty.PG_PORT.getName()));
  }

  /**
   * Tests the connect method by connecting to the test database.
   */
  @Test
  public void testConnect() throws Exception { // Test with the url, username & password
    Connection con =
        DriverManager.getConnection(getAwsURL(), TestUtil.getUser(), TestUtil.getPassword());
    assertNotNull(con);
    con.close();

    // Test with the username in the url
    con = DriverManager.getConnection(
        getAwsURL()
                + "&user=" + URLCoder.encode(TestUtil.getUser())
                + "&password=" + URLCoder.encode(TestUtil.getPassword()));
    assertNotNull(con);
    con.close();

    // Test with failover url
  }

  /*
   * Test that the readOnly property works.
   */
  @Test
  public void testReadOnly() throws Exception {
    Connection con = DriverManager.getConnection(getAwsURL() + "&readOnly=true",
        TestUtil.getUser(), TestUtil.getPassword());
    assertNotNull(con);
    assertTrue(con.isReadOnly());
    con.close();

    con = DriverManager.getConnection(getAwsURL() + "&readOnly=false", TestUtil.getUser(),
        TestUtil.getPassword());
    assertNotNull(con);
    assertFalse(con.isReadOnly());
    con.close();

    con =
        DriverManager.getConnection(getAwsURL(), TestUtil.getUser(), TestUtil.getPassword());
    assertNotNull(con);
    assertFalse(con.isReadOnly());
    con.close();
  }

  @Test
  public void testRegistration() throws Exception {
    // Driver is initially registered because it is automatically done when class is loaded
    assertTrue(software.aws.rds.jdbc.postgresql.Driver.isRegistered());

    ArrayList<java.sql.Driver> drivers = Collections.list(DriverManager.getDrivers());
    searchInstanceOf: {

      for (java.sql.Driver driver : drivers) {
        if (driver instanceof software.aws.rds.jdbc.postgresql.Driver) {
          break searchInstanceOf;
          }
      }
        fail("Driver has not been found in DriverManager's list but it should be registered");
    }

    // Deregister the driver
    Driver.deregister();
    assertFalse(Driver.isRegistered());

    drivers = Collections.list(DriverManager.getDrivers());
    for (java.sql.Driver driver : drivers) {
      if (driver instanceof software.aws.rds.jdbc.postgresql.Driver) {
        fail("Driver should be deregistered but it is still present in DriverManager's list");
      }
    }

    // register again the driver
    Driver.register();
    assertTrue(Driver.isRegistered());

    drivers = Collections.list(DriverManager.getDrivers());
    for (java.sql.Driver driver : drivers) {
      if (driver instanceof software.aws.rds.jdbc.postgresql.Driver) {
        return;
      }
    }
    fail("Driver has not been found in DriverManager's list but it should be registered");
  }

  @Test
  public void testSetLogWriter() throws Exception {

    // this is a dummy to make sure TestUtil is initialized
    Connection con = DriverManager.getConnection(getAwsURL(), TestUtil.getUser(), TestUtil.getPassword());
    con.close();
    String loggerLevel = System.getProperty("loggerLevel");
    String loggerFile = System.getProperty("loggerFile");

    PrintWriter prevLog = DriverManager.getLogWriter();
    try {
      PrintWriter printWriter = new PrintWriter(new NullOutputStream(System.err));
      DriverManager.setLogWriter(printWriter);
      assertEquals(DriverManager.getLogWriter(), printWriter);
      System.clearProperty("loggerFile");
      System.clearProperty("loggerLevel");
      Properties props = new Properties();
      props.setProperty("user", TestUtil.getUser());
      props.setProperty("password", TestUtil.getPassword());
      props.setProperty("loggerLevel", "DEBUG");
      con = DriverManager.getConnection(getAwsURL(), props);

      Logger logger = Logger.getLogger("software.aws.rds.jdbc.postgresql");
      Handler[] handlers = logger.getHandlers();
      assertTrue(handlers[0] instanceof LogWriterHandler );
      con.close();
    } finally {
      DriverManager.setLogWriter(prevLog);
      setProperty("loggerLevel", loggerLevel);
      setProperty("loggerFile", loggerFile);
    }
  }

  @Test
  public void testSetLogStream() throws Exception {
    // this is a dummy to make sure TestUtil is initialized
    Connection con = DriverManager.getConnection(getAwsURL(), TestUtil.getUser(), TestUtil.getPassword());
    con.close();
    String loggerLevel = System.getProperty("loggerLevel");
    String loggerFile = System.getProperty("loggerFile");

    try {
      DriverManager.setLogStream(new NullOutputStream(System.err));
      System.clearProperty("loggerFile");
      System.clearProperty("loggerLevel");
      Properties props = new Properties();
      props.setProperty("user", TestUtil.getUser());
      props.setProperty("password", TestUtil.getPassword());
      props.setProperty("loggerLevel", "DEBUG");
      con = DriverManager.getConnection(getAwsURL(), props);

      Logger logger = Logger.getLogger("software.aws.rds.jdbc.postgresql");
      Handler []handlers = logger.getHandlers();
      assertTrue( handlers[0] instanceof LogWriterHandler );
      con.close();
    } finally {
      DriverManager.setLogStream(null);
      setProperty("loggerLevel", loggerLevel);
      setProperty("loggerFile", loggerFile);
    }
  }

  private void setProperty(String key, String value) {
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }

  private String getAwsURL() {
    return TestUtil.getURL().replace("jdbc:postgresql://", "jdbc:postgresql:aws://");
  }
}
