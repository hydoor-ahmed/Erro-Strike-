pub fn get_service_info(service_name: &str) -> (&str, &str) {
    let name = service_name.to_lowercase();

    if name.contains("http") || name.contains("www") {
        ("Web Service", "🌐")
    } else if name.contains("ssh") {
        ("Secure Shell", "🔐")
    } else if name.contains("ftp") {
        ("File Transfer", "📁")
    } else if name.contains("sql") || name.contains("db") || name == "redis" {
        ("Database", "🗄️")
    } else if name.contains("mail") || name == "smtp" || name == "pop3" || name == "imap" {
        ("Email Service", "✉️")
    } else if name.contains("dns") || name == "domain" {
        ("Domain Name System", "📋")
    } else if name.contains("remote") || name == "rdp" || name == "vnc" {
        ("Remote Access", "🖥️")
    } else if name.contains("proxy") || name.contains("socks") {
        ("Proxy Service", "🕵️")
    } else if name == "eldim" || name == "elite" {
        ("Elite/Joke Port", "💀")
    } else {
        ("System Service", "⚙️")
    }
}
