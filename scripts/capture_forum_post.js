() => ({
  url: location.href,
  captured_at: new Date().toISOString(),
  authenticated: !!document.querySelector('a[href="usercp.php"]'),
  title: document.title,
  posts: [...document.querySelectorAll('.post[id^="post_"]')].map(node => ({
    id: node.id,
    author: node.querySelector('.post__user-profile a[href*="User-"]')?.textContent.trim() || null,
    permalink: node.querySelector('a[href*="?pid="]')?.href,
    html: node.querySelector('.post_body')?.outerHTML
  })),
  next: [...document.querySelectorAll('.pagination_next')].map(link => link.href)
})
