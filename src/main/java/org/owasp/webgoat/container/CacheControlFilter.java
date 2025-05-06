package org.owasp.webgoat.container;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * Filter to add Cache-Control headers to sensitive pages
 * to prevent them from being cached by browsers, proxies, or CDNs.
 * This addresses the security vulnerability "Sensitive Pages Could Be Cached".
 */
@Component
public class CacheControlFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        
        // Add no-cache headers to lesson content and sensitive pages
        if (requestURI.contains(".lesson") || 
            requestURI.contains("/WebGoat/") ||
            requestURI.contains("/xxe/")) {
            
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");
        }
        
        filterChain.doFilter(request, response);
    }
}