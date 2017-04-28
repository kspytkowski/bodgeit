<%@page import="org.owasp.esapi.Logger"%>
<%@page import="org.owasp.esapi.codecs.OracleCodec"%>
<%@page import="org.owasp.esapi.ESAPI"%>
<%@ page import="java.sql.*" %>

<%@ include file="/dbconnection.jspf" %>

<%
boolean loggedIn = false;
String username = (String) request.getParameter("username");
String password = (String) request.getParameter("password");
String debug = "Clear";

if (request.getMethod().equals("POST") && username != null) {
	OracleCodec oracleCodec = new OracleCodec();
	String encodedUsername = ESAPI.encoder().encodeForSQL(oracleCodec, username);
	String encodedPassword = ESAPI.encoder().encodeForSQL(oracleCodec, password);
	if (!username.equals(encodedUsername) || !password.equals(encodedPassword)) {
		ESAPI.log().error(Logger.SECURITY_FAILURE, 
				"Possible SQL Injection in login form - username: '" + username + "' password:'" + password + "'");
		ESAPI.intrusionDetector().addEvent("loginSQLInjection", "Possible SQL Injection in login form - username: '" + username + "' password:'" + password + "'");
	}
	PreparedStatement stmt = conn.prepareStatement("SELECT * FROM Users WHERE (name = ? AND password = ?)");
	ResultSet rs = null;
	try {
		stmt.setString(1, username);
		stmt.setString(2, password);
		rs = stmt.executeQuery();
		if (rs.next()) {
			loggedIn = true;
			debug="Logged in";
			// We must have been given the right credentials, right? ;)
			// Put credentials in the session
			String userid = "" + rs.getInt("userid");
			session = ESAPI.httpUtilities().changeSessionIdentifier(request);
			session.setAttribute("username", rs.getString("name"));
			session.setAttribute("userid", userid);
			session.setAttribute("usertype", rs.getString("type"));

			// Update the scores
			if (userid.equals("3")) {
				stmt.execute("UPDATE Score SET status = 1 WHERE task = 'LOGIN_TEST'");
			} else if (userid.equals("1")) {
				stmt.execute("UPDATE Score SET status = 1 WHERE task = 'LOGIN_USER1'");
			} else if (userid.equals("2")) {
				stmt.execute("UPDATE Score SET status = 1 WHERE task = 'LOGIN_ADMIN'");
			}

			Cookie[] cookies = request.getCookies();
			String basketId = null;
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					if (cookie.getName().equals("b_id") && cookie.getValue().length() > 0) {
						basketId = cookie.getValue();
						break;
					}
				}
			}
			if (basketId != null) {
				debug += " basketid = " + basketId;
				int cBasketId = rs.getInt("currentbasketid");
				if (cBasketId > 0) {
					// Merge baskets
					debug += " currentbasketid = " + cBasketId;
					stmt.execute("UPDATE BasketContents SET basketid = " + cBasketId + " WHERE basketid = " + basketId);

				} else {
					stmt.execute("UPDATE Users SET currentbasketid = " + basketId + " WHERE userid = " + userid);
				}
				response.addCookie(new Cookie("b_id", ""));
			}

		}
	} catch (Exception e) {
		if ("true".equals(request.getParameter("debug"))) {
			stmt.execute("UPDATE Score SET status = 1 WHERE task = 'HIDDEN_DEBUG'");
			out.println("DEBUG System error: " + e + "<br/><br/>");
		} else {
			out.println("System error.");
		}
	} finally {
		try {
			if (rs != null) {
				rs.close();
			}
		} catch (Exception e) {
			out.println("System error.");
		}
		try {
			if (stmt != null) {
				stmt.close();
			}
		} catch (Exception e) {
			out.println("System error.");
		}
	}
}
%>
<jsp:include page="/header.jsp"/>
<%
if ("true".equals(request.getParameter("debug"))) {
	out.println("DEBUG: " + debug + "<br/><br/>");
}
// Display the form
if (request.getMethod().equals("POST") && username != null) {
	if (loggedIn) {
		if (username.replaceAll("\\s", "").toLowerCase().indexOf("<script>alert(\"xss\")</script>") >= 0) {
			Statement stmt = conn.createStatement();
			try {
				stmt.execute("UPDATE Score SET status = 1 WHERE task = 'XSS_LOGIN'");
			} finally {
				stmt.close();
			}
		}
		out.println("<br/>You have logged in successfully: " + username);
		return;

	} else {
		out.println("<p style=\"color:red\">You supplied an invalid name or password.</p>");

	}
}
%>
<h3>Login</h3>
Please enter your credentials: <br/><br/>
<form method="POST">
	<center>
	<table>
	<tr>
		<td>Username:</td>
		<td><input id="username" name="username"/></td>
	</tr>
	<tr>
		<td>Password:</td>
		<td><input id="password" name="password" type="password"/></td>
	</tr>
	<tr>
		<td></td>
		<td><input id="submit" type="submit" value="Login"/></td>
	</tr>
	</table>
	</center>
</form>
If you dont have an account with us then please <a href="register.jsp">Register</a> now for a free account.
<br/><br/>

<jsp:include page="/footer.jsp"/>

