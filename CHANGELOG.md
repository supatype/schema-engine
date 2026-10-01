# Changelog

## [0.5.0](https://github.com/supatype/schema-engine/compare/v0.4.2...v0.5.0) (2026-10-01)


### Features

* **push:** report the schema's warnings in the push result ([8b0a9c6](https://github.com/supatype/schema-engine/commit/8b0a9c6fd65ca5b33e97e53e93059dcff3d90d74))
* **storage:** bucket rules as four operations, refused when left out ([dd0673b](https://github.com/supatype/schema-engine/commit/dd0673be2a3047d7bbf7650b15e4568ec2ce6304))


### Bug Fixes

* **generate:** set a relation to a model the seed builder has no type for by its key ([0bc4885](https://github.com/supatype/schema-engine/commit/0bc4885e83adbb2f7644da41ba196c9b7c26772d))
* **push,adopt:** read the database live, and refuse unmanaged tables by name ([687bade](https://github.com/supatype/schema-engine/commit/687badeae0d9873ff95dcb311b63c33762b43461))
* **push,adopt:** read the database live, and refuse unmanaged tables by name ([20e33a3](https://github.com/supatype/schema-engine/commit/20e33a30aa287bd71e6a2e846b42cd8dd851f22c)), closes [#86](https://github.com/supatype/schema-engine/issues/86) [#87](https://github.com/supatype/schema-engine/issues/87)
* **storage:** sweep stale policies with no buckets, refuse colliding names, warn on unreadable changes ([85b67e5](https://github.com/supatype/schema-engine/commit/85b67e5cc8de75b4c0b785be86eb2e5369ed3dbf))

## [0.4.2](https://github.com/supatype/schema-engine/compare/v0.4.1...v0.4.2) (2026-09-30)


### Bug Fixes

* **generate:** widen a localised rich text column inside the locale map ([c3c3040](https://github.com/supatype/schema-engine/commit/c3c30409d75f33fa1893784dfe15e84989b77c19))
* **generate:** widen a localised rich text column inside the locale map ([63c1c49](https://github.com/supatype/schema-engine/commit/63c1c49a9e21c14cb253b8cbe0d5f80a4c6bea4a))

## [0.4.1](https://github.com/supatype/schema-engine/compare/v0.4.0...v0.4.1) (2026-09-29)


### Bug Fixes

* **schema:** normalise a localised rich text column one locale at a time ([9d07513](https://github.com/supatype/schema-engine/commit/9d07513e907cbdf368cef0bff10c7833622816f7))
* **schema:** normalise a localised rich text column one locale at a time ([37fe388](https://github.com/supatype/schema-engine/commit/37fe3885a409028817029971d55e3b9d0523bef6))

## [0.4.0](https://github.com/supatype/schema-engine/compare/v0.3.3...v0.4.0) (2026-09-29)


### Features

* **access:** compose time operands with After and Before ([b75f925](https://github.com/supatype/schema-engine/commit/b75f9256b3ccdc2b08191cc9534b4a7f2ce27cea))
* **generate:** a rich text column reads as a document and writes as prose ([29ebd0f](https://github.com/supatype/schema-engine/commit/29ebd0fc6e559e1851d7ee21a010f48642c54405))
* **generate:** a rich text column reads as a document and writes as prose ([084d4ca](https://github.com/supatype/schema-engine/commit/084d4cab6e1ce349360072565c426b035b2d0863))
* **schema:** keep a rich text column holding a document ([ddf7880](https://github.com/supatype/schema-engine/commit/ddf78805e8942e984ce6acb97192edcbb8f1a29c))
* **seed:** generate a typed builder and apply a seed document ([f4d98db](https://github.com/supatype/schema-engine/commit/f4d98dbd8ce178e26ed7b872a8238a81ee107695))
* **seed:** record what has been seeded in _supatype.seeds ([7018a00](https://github.com/supatype/schema-engine/commit/7018a0069bfc28e99523e56b77d2910c49527cea))
* **seed:** the seed IR, its validator, planner and executor ([d10c54b](https://github.com/supatype/schema-engine/commit/d10c54bd1f0ce7f9006a2ded26ba8814ad31e56c))


### Bug Fixes

* **differ:** compare interval literals by value, and add After/Before ([0c33940](https://github.com/supatype/schema-engine/commit/0c33940b7de2c4b1eee35c847b9c66918c4480cd))
* **differ:** compare interval literals by value, not by spelling ([8ebd91d](https://github.com/supatype/schema-engine/commit/8ebd91d565db3d1ae99c397901450efc37180e29))
* **seed:** box the failure so the error fits in an async frame ([1bd1779](https://github.com/supatype/schema-engine/commit/1bd1779977df3b829023e1c31f44288b6e4dd1f6))
* **seed:** make nested writes and connect reach the database ([59b122e](https://github.com/supatype/schema-engine/commit/59b122e0c41fd30a6ea77ff87d7a92370ccc738d))
* the shared expression produced invalid SQL ([ddf7880](https://github.com/supatype/schema-engine/commit/ddf78805e8942e984ce6acb97192edcbb8f1a29c))

## [0.3.3](https://github.com/supatype/schema-engine/compare/v0.3.2...v0.3.3) (2026-09-27)


### Bug Fixes

* **differ:** stop proposing changes that are already applied ([de6b2df](https://github.com/supatype/schema-engine/commit/de6b2df4d3d1dfcbac1ff0ae93813aaf776acd04))
* **generator:** describe the column, not an approximation of it ([c823f3a](https://github.com/supatype/schema-engine/commit/c823f3a8d059c67cc25ff6725499a530fd200960))
* **storage:** grant the caller roles the select the policies need ([b73ef3b](https://github.com/supatype/schema-engine/commit/b73ef3bc2e78f496c882ffd92a71a287e078ac61))
