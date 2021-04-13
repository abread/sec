# driver

Continuously update the replicas state.

It accepts a JSON file with whatever the configuration is.


# Configuration

The JSON document has the following schema:

```
{
# grid dimensions
    "width": <uint>,
    "height": <uint>,
    "max_neighbourhood_faults": <uint>,

# clients
    "clients": [
        { "uri": <str>, "malicious": <bool> }, ...
    ]
}
```

Note: this configuration is type-checked at runtime. However, no attempt to verify that the clients are actually running (and running in the correct mode) is made.
The driver will fail if this happens.
