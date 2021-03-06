<%@page import="org.owasp.esapi.Logger"%>
<%@page import="org.owasp.esapi.ESAPI"%>
<%@ page import="java.sql.*" %>

<%@ include file="/dbconnection.jspf" %>
<jsp:include page="/header.jsp"/>

<%
	String usertype = (String) session.getAttribute("usertype");
	if (usertype != null && usertype.equals("ADMIN")) {
		out.println("<h3>Admin page</h3>");
		
		PreparedStatement stmt = null;
		ResultSet rs = null;
		try {
			stmt = conn.prepareStatement("SELECT * FROM Users");
			rs = stmt.executeQuery();
			out.println("<br/><center><table class=\"border\" width=\"80%\">");
			out.println("<tr><th>UserId</th><th>User</th><th>Role</th><th>BasketId</th></tr>");
			while (rs.next()) {
				out.println("<tr>");
				out.println("<td>" + rs.getInt("userid") + "</td><td>" + rs.getString("name") + 
						"</td><td>" + rs.getString("type") + "</td><td>" + rs.getInt("currentbasketid") + "</td>");
				out.println("</tr>");
			}
			out.println("</table></center><br/>");
			
			stmt = conn.prepareStatement("SELECT * FROM Baskets");
			rs = stmt.executeQuery();
			out.println("<br/><center><table class=\"border\" width=\"80%\">");
			out.println("<tr><th>BasketId</th><th>UserId</th><th>Date</th></tr>");
			while (rs.next()) {
				out.println("<tr>");
				out.println("<td>" + rs.getInt("basketid") + "</td><td>" + rs.getInt("userid") + 
						"</td><td>" + rs.getTimestamp("created") + "</td>");
				out.println("</tr>");
			}
			out.println("</table></center><br/>");
			
			stmt = conn.prepareStatement("SELECT * FROM BasketContents");
			rs = stmt.executeQuery();
			out.println("<br/><center><table class=\"border\" width=\"80%\">");
			out.println("<tr><th>BasketId</th><th>ProductId</th><th>Quantity</th></tr>");
			while (rs.next()) {
				out.println("<tr>");
				out.println("<td>" + rs.getInt("basketid") + "</td><td>" + rs.getInt("productid") + 
						"</td><td>" + rs.getInt("quantity") + "</td>");
				out.println("</tr>");
			}
			out.println("</table></center><br/>");
		} catch (SQLException e) {
			out.println("System error.<br/>" + e);
		} finally {
			if (stmt != null) {
				stmt.close();
			}
			if (rs != null) {
				rs.close();
			}
		}
	} else {
		ESAPI.intrusionDetector().addEvent("adminUnauthorizedAccess", "Attempt of unauthorized access to admin page");
		ESAPI.log().error(Logger.SECURITY_FAILURE, "Unauthorized attempt to see admin page"); 
		out.println("<h3>You are not allowed to see this page</h3>");
	}
%>

<jsp:include page="/footer.jsp"/>

