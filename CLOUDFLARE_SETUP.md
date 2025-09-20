# Cloudflare + nginx Setup Guide for ircquotes

## Overview
This setup ensures that your ircquotes application can see real client IP addresses even when behind:
1. **Cloudflare** (CDN/Proxy)
2. **nginx** (Reverse Proxy)
3. **Gunicorn** (WSGI Server)

## Architecture
```
Client → Cloudflare → nginx → Gunicorn → ircquotes
```

## Setup Steps

### 1. Cloudflare Configuration

#### Enable Proxy (Orange Cloud)
- Set your DNS record to "Proxied" (orange cloud icon)
- This routes traffic through Cloudflare's edge servers

#### Recommended Cloudflare Settings:
- **SSL/TLS**: Full (Strict) if you have SSL on origin
- **Security Level**: Medium
- **Bot Fight Mode**: Enabled
- **Rate Limiting**: Configure as needed
- **Page Rules**: Optional caching rules

#### Important Headers:
Cloudflare automatically adds these headers:
- `CF-Connecting-IP`: Real client IP address
- `CF-Ray`: Request identifier
- `CF-Visitor`: Visitor information

### 2. nginx Configuration

Copy the provided `nginx-ircquotes.conf` to your nginx sites:

```bash
sudo cp nginx-ircquotes.conf /etc/nginx/sites-available/ircquotes
sudo ln -s /etc/nginx/sites-available/ircquotes /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

**Key nginx features:**
- ✅ Cloudflare IP range restoration
- ✅ Real IP detection via CF-Connecting-IP
- ✅ Additional rate limiting layer
- ✅ Security headers
- ✅ Gzip compression
- ✅ Static file optimization

### 3. Application Configuration

The ircquotes app is already configured to:
- ✅ Use `CF-Connecting-IP` header (Cloudflare's real IP)
- ✅ Fall back to `X-Forwarded-For` and `X-Real-IP`
- ✅ Handle 2-proxy setup (Cloudflare + nginx)
- ✅ Rate limit by real client IP

### 4. Verification

To verify real IPs are being detected:

1. **Check application logs**:
   ```bash
   tail -f /var/log/ircquotes/access.log
   ```

2. **Test from different locations**:
   - Visit your site from different networks
   - Check admin panel for real IPs in quote submissions
   - Verify rate limiting works per real IP

3. **Debug headers** (temporary debug route):
   ```python
   @app.route('/debug-headers')
   def debug_headers():
       return jsonify({
           'real_ip': get_real_ip(),
           'cf_connecting_ip': request.headers.get('CF-Connecting-IP'),
           'x_forwarded_for': request.headers.get('X-Forwarded-For'),
           'x_real_ip': request.headers.get('X-Real-IP'),
           'remote_addr': request.remote_addr
       })
   ```

### 5. Security Considerations

#### Cloudflare Settings:
- Enable **DDoS Protection**
- Configure **WAF Rules** for your application
- Set up **Rate Limiting** at Cloudflare level
- Enable **Bot Management** if available

#### nginx Security:
- Keep Cloudflare IP ranges updated
- Monitor for suspicious patterns
- Implement additional rate limiting
- Regular security updates

#### Application Security:
- All security features already implemented
- Rate limiting per real IP
- CSRF protection enabled
- Input validation active

## Troubleshooting

### IPs showing as 127.0.0.1:
1. Check nginx is passing headers correctly
2. Verify Cloudflare IP ranges in nginx config
3. Ensure ProxyFix is configured for 2 proxies
4. Check `CF-Connecting-IP` header presence

### Rate limiting not working:
1. Verify real IP detection is working
2. Check rate limiting configuration
3. Monitor nginx and application logs
4. Test with different source IPs

### Performance issues:
1. Enable nginx caching for static files
2. Configure Cloudflare caching rules
3. Monitor Gunicorn worker count
4. Check database connection pooling

## Monitoring

Recommended monitoring:
- **Application logs**: Real IP addresses in logs
- **nginx access logs**: Request patterns
- **Cloudflare Analytics**: Traffic patterns
- **Rate limiting metrics**: Blocked vs allowed requests

## Production Checklist

- [ ] Cloudflare proxy enabled (orange cloud)
- [ ] nginx configuration deployed
- [ ] Real IP detection working
- [ ] Rate limiting functional
- [ ] Security headers present
- [ ] SSL/TLS configured
- [ ] Monitoring in place
- [ ] Backup and recovery tested