rule {{ name }}
{
    {% if comment -%}
    /*
    {% for line in comment -%}
        {{ line }}
    {% endfor -%}
    */
    {%- endif %}
    {% if string_detections or hex_detections or re_detections -%}
    strings:
        {% for x in string_detections -%}
        $str_{{ loop.index }} = "{{ x }}"
        {% endfor -%}
        {% for x in hex_detections -%}
        $hex_{{ loop.index }} = { {{ x }} }
        {% endfor -%}
        {% for x in re_detections -%}
        $re_{{ loop.index }} = /{{ x }}/
        {% endfor -%}
    {%- endif %}

    condition:
        all of them
}
