<%@page import="org.owasp.esapi.errors.IntrusionException"%>
<%@page import="org.owasp.esapi.errors.ValidationException"%>
<%@ page import="org.owasp.esapi.ESAPI"%>
<%@ page import="java.sql.*" %>

<%@ include file="/dbconnection.jspf" %>

<%
String username = (String) request.getParameter("username");
String password1 = (String) request.getParameter("password1");
String password2 = (String) request.getParameter("password2");
String usertype = (String) session.getAttribute("usertype");
String userid = (String) session.getAttribute("userid");
String debug = "";
String result = null;
boolean registered = false;

if (request.getMethod().equals("POST") && username != null) {
	try {
		username = ESAPI.validator().getValidInput("Validating username", username, "Email", 100, false);
		if (password1 == null || password1.length() < 5) {
			result = "You must supply a password of at least 5 characters.";
		} else if (password1.equals(password2)) {
			PreparedStatement insertUserStmt = conn.prepareStatement("INSERT INTO Users (name, type, password) VALUES (?, 'USER', ?)");
			PreparedStatement selectUsersStmt = conn.prepareStatement("SELECT * FROM Users WHERE (name = ? AND password = ?)");
			PreparedStatement updateUserBasketIdStmt = conn.prepareStatement("UPDATE Users SET currentbasketid = ? WHERE userid = ?");
			PreparedStatement updateBasketUserIdStmt = conn.prepareStatement("UPDATE Baskets SET userid = ? WHERE basketid = ?");
			ResultSet rs = null;
			try {
				insertUserStmt.setString(1, username);
				insertUserStmt.setString(2, password1);
				insertUserStmt.executeQuery();
				selectUsersStmt.setString(1, username);
				selectUsersStmt.setString(2, password1);
				rs = selectUsersStmt.executeQuery();
				rs.next();
				userid =  "" + rs.getInt("userid"); 
	
				session.setAttribute("username", username);
				session.setAttribute("usertype", "USER");
				session.setAttribute("userid", userid);
	
				
				if (username.replaceAll("\\s", "").toLowerCase().indexOf("<script>alert(\"xss\")</script>") >= 0) {
					conn.createStatement().execute("UPDATE Score SET status = 1 WHERE task = 'XSS_USER'");
				}
	
				registered = true;
	
				// Update basket
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
					debug +=  " userId = " + userid + " basketId = " + basketId;
					// TODO breaks basket scoring :(
					updateUserBasketIdStmt.setString(1, basketId);
					updateUserBasketIdStmt.setString(2, userid);
					updateUserBasketIdStmt.executeQuery();		
					updateBasketUserIdStmt.setString(1, userid);
					updateBasketUserIdStmt.setString(2, basketId);
					updateBasketUserIdStmt.executeQuery();
					response.addCookie(new Cookie("b_id", ""));
				}
				
			} catch (SQLException e) {
				if (e.getMessage().indexOf("Unique constraint violation") >= 0) {
					result = "A user with this name already exists.";
				} else {
					if ("true".equals(request.getParameter("debug"))) {
						conn.createStatement().execute("UPDATE Score SET status = 1 WHERE task = 'HIDDEN_DEBUG'");
						out.println("DEBUG System error: " + e + "<br/><br/>");
					} else {
						out.println("System error.");
					}
				}
			} catch (Exception e) {
				if ("true".equals(request.getParameter("debug"))) {
					conn.createStatement().execute("UPDATE Score SET status = 1 WHERE task = 'HIDDEN_DEBUG'");
					out.println("DEBUG System error: " + e + "<br/><br/>");
				} else {
					out.println("System error.");
				}
			} finally {
				try {
					if (insertUserStmt != null) {
						insertUserStmt.close();
					}
				} catch (Exception e) {
					out.println("System error.");
				}
				try {
					if (selectUsersStmt != null) {
						selectUsersStmt.close();
					}
				} catch (Exception e) {
					out.println("System error.");
				}
				try {
					if (updateUserBasketIdStmt != null) {
						updateUserBasketIdStmt.close();
					}
				} catch (Exception e) {
					out.println("System error.");
				}
				try {
					if (updateBasketUserIdStmt != null) {
						updateBasketUserIdStmt.close();
					}
				} catch (Exception e) {
					out.println("System error.");
				}
			}
		} else {
			result = "The passwords you have supplied are different.";
		}
	} catch (ValidationException e) {
		result = e.getUserMessage();
 	} catch (IntrusionException ie) {
 		result = ie.getUserMessage();
 	}
}
%>

<jsp:include page="/header.jsp"/>
<h3>Register</h3>
<%
if ("true".equals(request.getParameter("debug"))) {
	conn.createStatement().execute("UPDATE Score SET status = 1 WHERE task = 'HIDDEN_DEBUG'");
	out.println("DEBUG: " + debug + "<br/><br/>");
}

if (registered) {
	out.println("<br/>You have successfully registered with The BodgeIt Store.");
%>
	<jsp:include page="/footer.jsp"/>
<%
	return;
	
} else if (result != null) {
	out.println("<p style=\"color:red\">" + result + "</p><br/>");
}
%>

Please enter the following details to register with us: <br/><br/>
<form method="POST">
	<center>
	<table>
	<tr>
		<td>Username (your email address):</td>
		<td><input id="username" name="username"></input></td>
	</tr>
	<tr>
		<td>Password:</td>
		<td><input id="password1" name="password1" type="password"></input></td>
	</tr>
	<tr>
		<td>Confirm Password:</td>
		<td><input id="password2" name="password2" type="password"></input></td>
	</tr>
	<tr>
		<td></td>
		<td><input id="submit" type="submit" value="Register"></input></td>
	</tr>
	</table>
	</center>
</form>

<jsp:include page="/footer.jsp"/>

