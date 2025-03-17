#ifndef TYPES_H
#define TYPES_H

struct Vec3 {
    float x;
    float y;
    float z;

    Vec3() : x(0.0f), y(0.0f), z(0.0f) {}
    bool is_zero() const { return x == 0.0f && y == 0.0f && z == 0.0f; }
    bool is_below_specific_z(int spec_z) const { 
        return static_cast<int>(z) < spec_z;
    }
};

#endif