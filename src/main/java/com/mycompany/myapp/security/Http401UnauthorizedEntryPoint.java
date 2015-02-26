package com.mycompany.myapp.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * Returns a 401 error code (Unauthorized) to the client.
 */
@Component
public class Http401UnauthorizedEntryPoint implements AuthenticationEntryPoint {

	private final Logger log = LoggerFactory.getLogger(Http401UnauthorizedEntryPoint.class);

	public Http401UnauthorizedEntryPoint() {
		super();
	}

	@Override
	public void commence(final HttpServletRequest request,
			final HttpServletResponse response,
			final AuthenticationException authException) throws IOException,
			ServletException {
		if (isPreflight(request)) {
			log.debug("Allowing Preflight OPTIONS request");
			response.setStatus(HttpServletResponse.SC_NO_CONTENT);
		} else {
			log.debug("Request to entry point is unauthorized. Rejecting access");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
					"Unauthorized");
		}
	}

	/**
	 * Checks if this is a X-domain pre-flight request.
	 * 
	 * @param request
	 * @return
	 */
	private boolean isPreflight(HttpServletRequest request) {
		return "OPTIONS".equals(request.getMethod());
	}
}
