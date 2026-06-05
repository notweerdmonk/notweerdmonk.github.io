---
layout: default
title: "Tags"
permalink: /tags/
---
<div class="article">
<section class="article-body">
<h1>Tags</h1>
<table style="max-width: unset;width: 100%">
{% capture all_tags_str %}{% endcapture %}
{% comment %}Collect tags from the collection "items"{% endcomment %}
{% for doc in site.items %}
  {% if doc.tags %}
    {% for t in doc.tags %}
      {% capture slug %}{{ t | slugify }}{% endcapture %}
      {% capture all_tags_str %}{{ all_tags_str }}|{{ slug }}{% endcapture %}
    {% endfor %}
  {% endif %}
{% endfor %}

{% comment %}Fallback: include tags from posts too (optional) {% endcomment %}
{% for tagpair in site.tags %}
  {% assign name = tagpair[0] %}
  {% capture tslug %}{{ name | slugify }}{% endcapture %}
  {% capture all_tags_str %}{{ all_tags_str }}|{{ tslug }}{% endcapture %}
{% endfor %}

{% comment %}Turn the string into an array, remove empty entries, get unique slugs{% endcomment %}
{% assign all_tags_array = all_tags_str | split: '|' %}
{% assign unique = all_tags_array | uniq | sort %}

{% comment %}For each unique slug, count occurrences in all_tags_array{% endcomment %}
{% for u in unique %}
  {% if u and u != "" %}
    <tr>
    {% assign count = 0 %}
    {% for s in all_tags_array %}
      {% if s == u %}
        {% assign count = count | plus: 1 %}
      {% endif %}
    {% endfor %}
    {% assign display = u | replace: '-', ' ' %}
    <td>
      <a href="{{ '/tags/' | append: u | append: '/' | relative_url }}">{{ display }}</a>
    </td>
    <td>
      {{ count }}
    </td>
  </tr>
  {% endif %}
{% endfor %}
</table>
</section>
</div>
