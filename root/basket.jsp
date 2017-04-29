<%@page import="org.owasp.esapi.reference.DefaultEncoder"%>
<%@page import="org.owasp.esapi.ESAPI"%>
<%@page import="org.owasp.esapi.errors.IntrusionException"%>
<%@page import="java.net.URL"%>
<%@ page import="javax.servlet.http.*" %>
<%@ page import="java.sql.*" %>
<%@ page import="java.math.*" %>
<%@ page import="java.text.*" %>
<%@ page import="java.util.*" %>
<%@ page import="org.owasp.esapi.*" %>

<%@ include file="/dbconnection.jspf" %>

<script type="text/javascript">
    function incQuantity (prodid) {
    var q = document.getElementById('quantity_' + prodid);
    if (q != null) {
        var val = ++q.value;
        if (val > 12) {
            val = 12;
        }
        q.value = val;
    }
}
function decQuantity (prodid) {
    var q = document.getElementById('quantity_' + prodid);
    if (q != null) {
        var val = --q.value;
        if (val < 0) {
            val = 0;
        }
        q.value = val;
    }
}
</script>

<jsp:include page="/header.jsp"/>

<h3>Your Basket</h3>
<%
	String userid = (String) session.getAttribute("userid");
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
		// Dont need to do anything else
			
		// Well, apart from checking to see if they've accessed someone elses basket ;)
		PreparedStatement stmt = conn.prepareStatement("SELECT userid FROM Baskets WHERE basketid = ?");
		try {
			stmt.setString(1, basketId);
			ResultSet rs = stmt.executeQuery();
			if (rs.next()) {
				String bUserId = String.valueOf(rs.getInt("userid"));
				if ((userid == null && !bUserId.equals("0")) || (userid != null && !userid.equals(bUserId))) {
					basketId = "-1";
					ESAPI.intrusionDetector().addEvent("basketIdChangedCookiePoisoning", "Cookie poisoning detected - basket id in cookie is not coupled with logged user");
				}
			}
		} catch (Exception e) {
			ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
		} finally {
			stmt.close();
		}

	} else if (userid == null) {
		// Not logged in, and no basket, so create one
		Statement stmt = conn.createStatement();
		try {
			Timestamp ts = new Timestamp((new java.util.Date()).getTime());
			stmt.execute("INSERT INTO Baskets (created) VALUES ('" + ts + "')");
			ResultSet rs = stmt.executeQuery("SELECT * FROM Baskets WHERE created = '" + ts + "'");
			rs.next();
			basketId = "" + rs.getInt("basketid");

			response.addCookie(new Cookie("b_id", basketId));

		} catch (Exception e) {
			ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
			return;

		} finally {
			stmt.close();
		}
	} else {
		PreparedStatement stmt = conn.prepareStatement("SELECT * FROM Users WHERE userid = ?");
		try {
			int usId = Integer.valueOf(userid);
			stmt.setInt(1, usId);
			ResultSet rs = stmt.executeQuery();
			if (rs.next()) {
				int bId = rs.getInt("currentbasketid");
				if (bId > 0) {
					basketId = String.valueOf(bId);
				} else {
					// Need to create one
					Timestamp ts = new Timestamp((new java.util.Date()).getTime());
					stmt.execute("INSERT INTO Baskets (created, userid) VALUES ('" + ts + "', " + userid + ")");
					rs = stmt.executeQuery("SELECT * FROM Baskets WHERE (userid = " + userid + ")");
					rs.next();
					basketId = "" + rs.getInt("basketid");
					stmt.execute("UPDATE Users SET currentbasketid = " + basketId + " WHERE userid = " + userid);
				}
			}
			
		} catch (SQLException e) {
			ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
			return;
		} catch (Exception e) {
			ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
			return;
		} finally {
			stmt.close();
		}
		
	}
	
	PreparedStatement stmt = null;
	ResultSet rs = null;

	String update = request.getParameter("update");
	String productId = request.getParameter("productid");
	String csrf = request.getParameter("csrf");
	
	if (productId != null && request.getParameterMap().containsKey("quantity")) {
                //Check for CSRF for Scoring by looking at the referrer
                String referer = request.getHeader("referer");
                //Set URL, if referer field is blank, someone is messing with things and probably gets this challenge
                URL url = (referer == null) ? new URL("https://www.google.com") : new URL(referer);
                if(!url.getFile().startsWith(request.getContextPath() + "/product.jsp?prodid=")){
                    conn.createStatement().execute("UPDATE Score SET status = 1 WHERE task = 'CSRF_BASKET'");
                }
		if (csrf != null && csrf.equals(request.getSession().getAttribute("csrf"))) {
			// Add product
			int quantity = Integer.valueOf(request.getParameter("quantity"));
			try {
				// Product in basket?
				int currentQuantity = 0;
				
				stmt = conn.prepareStatement("SELECT * FROM BasketContents WHERE basketid= ? AND productid = ?");
				stmt.setInt(1, Integer.valueOf(basketId));
				stmt.setInt(2, Integer.valueOf(productId));
				rs = stmt.executeQuery();
				if (rs.next()) {
	                quantity = quantity + rs.getInt("quantity");
					rs.close();
					stmt.close();
					if (quantity >=0) {
						stmt = conn.prepareStatement("UPDATE BasketContents SET quantity = " + quantity + 
								" WHERE basketid=" + basketId + " AND productid = " + productId);
						stmt.execute();
					}
				} else {
					rs.close();
					stmt.close();
					if (quantity >= 0) {
						stmt = conn.prepareStatement("SELECT * FROM Products where productid=" + productId);
						rs = stmt.executeQuery();
						if (rs.next()) {
							Double price = rs.getDouble("price"); 
							rs.close();
							stmt.close();
							stmt = conn.prepareStatement("INSERT INTO BasketContents (basketid, productid, quantity, pricetopay) VALUES (" +
									basketId + ", " + productId + ", " + quantity + ", " + price + ")");
							stmt.execute();
						}
					}
				}
				if (quantity < 0) {
					ESAPI.intrusionDetector().addEvent("basketNegativeQuantity", "Request alternating detected - negative quantity of basket");
				}
				out.println("Your basket had been updated.<br/>");
			} catch (SQLException e) {
				ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
			} finally {
				if (stmt != null) {
					stmt.close();
				}
				if (rs != null) {
					rs.close();
				}
			}
		} else {
			ESAPI.log().error(Logger.SECURITY_FAILURE, "CSRF attack found (adding product to basket)");
			ESAPI.intrusionDetector().addEvent("basketAddProductCSRF", "Detected CSRF attack on basket page");
			out.println("<p style=\"color:red\">Intrusion detection (valid CSRF Token not found). Someone wanted to add product to Your basket!</p><br/>");	
		}
	} else if (update != null) {
		if (csrf != null && csrf.equals(request.getSession().getAttribute("csrf"))) {
			// Update the basket
			Map params = request.getParameterMap();
			Iterator iter = params.entrySet().iterator();
			while (iter.hasNext()) {
				Map.Entry entry = (Map.Entry) iter.next();
				String key = (String) entry.getKey();
				String value = ((String[]) entry.getValue())[0];
				if (key.startsWith("quantity_")) {
					String prodId = key.substring(9);
					int quantity = Integer.parseInt(value);
					if (quantity == 0) {
						stmt = conn.prepareStatement("DELETE FROM BasketContents WHERE basketid=" + basketId +
								" AND productid = " + prodId);
						stmt.execute();
						stmt.close();						
					} else if (quantity > 0) {
						stmt = conn.prepareStatement("UPDATE BasketContents SET quantity = " + quantity + " WHERE basketid=" + basketId +
								" AND productid = " + prodId);
						stmt.execute();
					}
				}
			}
			out.println("<p style=\"color:green\">Your basket had been updated.</p><br/>");
		} else {
			ESAPI.log().error(Logger.SECURITY_FAILURE, "CSRF attack found (updating basket)");
			ESAPI.intrusionDetector().addEvent("basketUpdateCSRF", "Detected CSRF attack on basket page");
			out.println("<p style=\"color:red\">Intrusion detection (valid CSRF Token not found). Someone wanted to update Your basket!</p><br/>");
		}
	}
	
	// Display basket
	try {
		stmt = conn.prepareStatement("SELECT * FROM BasketContents, Products where basketid=" + basketId + 
				" AND BasketContents.productid = Products.productid");
		rs = stmt.executeQuery();
		out.println("<form action=\"basket.jsp\" method=\"post\">");
		csrf = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		request.getSession().setAttribute("csrf", csrf);
		out.println("<input type=\"hidden\" id=\"csrf\" name=\"csrf\" value=\"" + csrf + "\"/>");
		out.println("<table border=\"1\" class=\"border\" width=\"80%\">");
		out.println("<tr><th>Product</th><th>Quantity</th><th>Price</th><th>Total</th></tr>");
		BigDecimal basketTotal = new BigDecimal(0);
		NumberFormat nf = NumberFormat.getCurrencyInstance();
		while (rs.next()) {
			out.println("<tr>");
			String product = rs.getString("product");
			int prodId = rs.getInt("productid");
			BigDecimal pricetopay = rs.getBigDecimal("pricetopay");
			int quantity = rs.getInt("quantity");
			BigDecimal total = pricetopay.multiply(new BigDecimal(quantity));
			basketTotal = basketTotal.add(total);
			
			out.println("<td><a href=\"product.jsp?prodid=" + rs.getInt("productid") + "\">" + product + "</a></td>"); 
			out.println("<td style=\"text-align: center\">&nbsp;<a href=\"#\" onclick=\"decQuantity(" + prodId + ");\"><img src=\"images/130.png\" alt=\"Decrease quantity in basket\" border=\"0\"></a>&nbsp;" +
					"<input id=\"quantity_" + prodId + "\" name=\"quantity_" + prodId + "\" value=\"" + quantity + "\" maxlength=\"2\" size = \"2\" " +
					"style=\"text-align: right\" READONLY />&nbsp;<a href=\"#\" onclick=\"incQuantity(" + prodId + ");\"><img src=\"images/129.png\" alt=\"Increase quantity in basket\" border=\"0\"></a>&nbsp;" +
					"</td>");
			out.println("<td align=\"right\">" + nf.format(pricetopay) + "</td>");
			out.println("</td><td align=\"right\">" + nf.format(total) + "</td>");
			out.println("</tr>");
		}
		out.println("<tr><td>Total</td><td style=\"text-align: center\">" + "<input id=\"update\" name=\"update\" type=\"submit\" value=\"Update Basket\"/>" + "</td><td>&nbsp;</td>" +
				"<td align=\"right\">" + nf.format(basketTotal) + "</td></tr>");
		out.println("</table>");
		out.println();
		out.println("</form>");
	
	} catch (SQLException e) {
		ESAPI.log().error(Logger.EVENT_FAILURE, e.getLocalizedMessage());
		out.println("System error.");
	} finally {
		if (stmt != null) {
			stmt.close();
		}
		if (rs != null) {
			rs.close();
		}
	}

%>
<jsp:include page="/footer.jsp"/>

