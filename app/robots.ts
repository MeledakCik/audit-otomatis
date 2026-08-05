import { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        disallow: ['/api/', '/scan', '/requests'],
      },
    ],
    sitemap: 'https://www.sentinel-id.net/sitemap.xml',
  }
}