def get_group_elements(p):
    # Find a generator of the group (Z/pZ)*
    for g in range(2, p):
        if pow(g, p-1, p) == 1:
            break

    # Iterate over all elements in the group (Z/pZ)* using the generator
    elements = []
    for i in range(0, p):
        elements.append(str(pow(g, i, p)))

    # Output each element
    return ' '.join(elements)

# Test with p = 23
print(get_group_elements(23))