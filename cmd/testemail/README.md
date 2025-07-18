# Email Testing Tool

This command-line tool allows you to test the email functionality of the OpenID Provider service. It reads your existing configuration file and sends a simple test email to verify your SMTP settings are working correctly.

## Usage

```bash
testemail -to recipient@example.com [options]
```

## Options

- `-to string`: Recipient email address (required)
- `-config string`: Path to configuration file (defaults to standard location: `~/.config/openidprovider/openidprovider.json`)
- `-help`: Show help message

## Examples

### Basic usage (uses default config location)
```bash
testemail -to test@example.com
```

### Test with custom config file
```bash
testemail -to test@example.com -config /path/to/config.json
```

## Configuration

The tool reads the same configuration file as the main OpenID Provider service. Make sure your configuration file includes the SMTP settings:

```json
{
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "fromEmail": "noreply@yourdomain.com",
    "fromName": "Your Application Name",
    "useTls": true
  }
}
```
