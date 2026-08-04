/*
 * ff7_field_captions.h -- GENERATED FILE, do not edit by hand.
 *
 * Every field's FRIENDLY caption ("Mako Reactor 1"), harvested offline
 * from each field's own MPNAM opcode (0x43) in flevel.lgp by
 * investigate/ff7_mpnam_caption_catalog.py (2026-08-04).
 * Index = field id (the FF7FieldNames::kNames id space). L"" = the
 * field's scripts set no MPNAM (at runtime it inherits the previous
 * field's caption -- callers fall through to the visited-places cache
 * and then the internal maplist name).
 *
 * Decoded with an exact mirror of FF7Text::DecodeChar and truncated to
 * 23 chars, so an entry here is byte-identical to what PlacesLearn
 * stores when the player actually visits the field -- name identity
 * (dedupe, journey comparisons) is preserved across the two sources.
 * Validated against the live-learned ffvii_accessibility_places.txt
 * captions from real play (ids 116-124) at generation time.
 *
 * WHY THIS EXISTS (v2.30.86): exits/journeys used to speak internal map
 * codes ("To nmkin 2") for unvisited destinations; testers read that as
 * name-obscuring. Real names now speak everywhere, with ", unexplored"
 * appended by the callers when the visited cache has no entry.
 */

#pragma once

namespace FF7FieldCaptions {

constexpr int kCount = 788;

inline const wchar_t* const kCaptions[kCount] = {
    L"",   // 0
    L"",   // 1
    L"",   // 2
    L"",   // 3
    L"",   // 4
    L"",   // 5
    L"",   // 6
    L"",   // 7
    L"",   // 8
    L"",   // 9
    L"",   // 10
    L"",   // 11
    L"",   // 12
    L"",   // 13
    L"",   // 14
    L"",   // 15
    L"",   // 16
    L"",   // 17
    L"",   // 18
    L"",   // 19
    L"",   // 20
    L"",   // 21
    L"",   // 22
    L"",   // 23
    L"",   // 24
    L"",   // 25
    L"",   // 26
    L"",   // 27
    L"",   // 28
    L"",   // 29
    L"",   // 30
    L"",   // 31
    L"",   // 32
    L"",   // 33
    L"",   // 34
    L"",   // 35
    L"",   // 36
    L"",   // 37
    L"",   // 38
    L"",   // 39
    L"",   // 40
    L"",   // 41
    L"",   // 42
    L"",   // 43
    L"",   // 44
    L"",   // 45
    L"",   // 46
    L"",   // 47
    L"",   // 48
    L"",   // 49
    L"",   // 50
    L"",   // 51
    L"",   // 52
    L"",   // 53
    L"",   // 54
    L"",   // 55
    L"",   // 56
    L"",   // 57
    L"",   // 58
    L"",   // 59
    L"",   // 60
    L"",   // 61
    L"",   // 62
    L"",   // 63
    L"",   // 64
    L"",   // 65
    L"",   // 66
    L"deck",   // 67
    L"",   // 68
    L"",   // 69
    L"Highwind",   // 70
    L"Bridge",   // 71
    L"Highwind",   // 72
    L"Highwind",   // 73
    L"",   // 74
    L"Inside airship",   // 75
    L"Highwind",   // 76
    L"",   // 77
    L"Old man's house",   // 78
    L"Weapon seller",   // 79
    L"Mystery House",   // 80
    L"???",   // 81
    L"",   // 82
    L"",   // 83
    L"",   // 84
    L"",   // 85
    L"",   // 86
    L"",   // 87
    L"Hallway",   // 88
    L"Hallway",   // 89
    L"Research Room",   // 90
    L"Cargo Room",   // 91
    L"",   // 92
    L"",   // 93
    L"",   // 94
    L"DEBUG MODE",   // 95
    L"",   // 96
    L"",   // 97
    L"",   // 98
    L"DEBUG",   // 99
    L"",   // 100
    L"",   // 101
    L"",   // 102
    L"Midgar Highway",   // 103
    L"",   // 104
    L"",   // 105
    L"",   // 106
    L"",   // 107
    L"",   // 108
    L"BLACKBGH",   // 109
    L"BLACKBGI",   // 110
    L"",   // 111
    L"Dark city fourth street",   // 112
    L"",   // 113
    L"",   // 114
    L"",   // 115
    L"Platform",   // 116
    L"Sector 1 Station",   // 117
    L"Sector 1",   // 118
    L"No.1 Reactor",   // 119
    L"No.1 Reactor",   // 120
    L"No.1 Reactor",   // 121
    L"No.1 Reactor",   // 122
    L"No.1 Reactor",   // 123
    L"No.1 Reactor",   // 124
    L"No.1 Reactor",   // 125
    L"No.5 Reactor",   // 126
    L"",   // 127
    L"No.5 Reactor",   // 128
    L"No.5 Reactor",   // 129
    L"No.5 Reactor",   // 130
    L"No.5 Reactor",   // 131
    L"No.5 Reactor",   // 132
    L"Sector 8",   // 133
    L"Sector 8",   // 134
    L"Sector 8",   // 135
    L"No.1 Reactor",   // 136
    L"Sector 8",   // 137
    L"Last Train from Midgar",   // 138
    L"Last Train from Midgar",   // 139
    L"Inside Train",   // 140
    L"Inside Train",   // 141
    L"Inside Train",   // 142
    L"Last Train from Midgar",   // 143
    L"Train Graveyard",   // 144
    L"Train Graveyard",   // 145
    L"Sector 7 Station",   // 146
    L"",   // 147
    L"Sector 7 Weapon Shop",   // 148
    L"Beginner's Hall",   // 149
    L"Sector 7 Slums",   // 150
    L"Sector 7 Slums",   // 151
    L"Sector 7 Item Store",   // 152
    L"Johnny's Home",   // 153
    L"7th Heaven",   // 154
    L"AVALANCHE Hideout",   // 155
    L"Sector 7 Slums",   // 156
    L"Sector 7 Mechanized Tow",   // 157
    L"Plate Support",   // 158
    L"Plate Support",   // 159
    L"Plate Support",   // 160
    L"Winding Tunnel",   // 161
    L"Winding Tunnel",   // 162
    L"Winding Tunnel",   // 163
    L"4th Street Plate Int.",   // 164
    L"4th Street Plate Int.",   // 165
    L"4th Street Plate Int.",   // 166
    L"Lower Sector 4 Plate",   // 167
    L"Lower Sector 4 Plate",   // 168
    L"Lower Sector 4 Plate",   // 169
    L"Slum Outskirts",   // 170
    L"Sector 5 Slum",   // 171
    L"Sector 5 Slum",   // 172
    L"",   // 173
    L"House 1f.",   // 174
    L"House 2f.",   // 175
    L"Earthen Pipe",   // 176
    L"Sector 5 Slum",   // 177
    L"Weapon Store",   // 178
    L"Item Store",   // 179
    L"Materia store",   // 180
    L"Church",   // 181
    L"church in the slums",   // 182
    L"church in the slums",   // 183
    L"Inside the Church",   // 184
    L"Church Roof",   // 185
    L"Church Roof",   // 186
    L"'s House",   // 187
    L"'s House",   // 188
    L"",   // 189
    L"'s House",   // 190
    L"Sector 6",   // 191
    L"Sector 6 park",   // 192
    L"Sector 6 park",   // 193
    L"Sector 6",   // 194
    L"Wall Market",   // 195
    L"Weapon Store",   // 196
    L"Men's Hall",   // 197
    L"Item Store",   // 198
    L"Inn",   // 199
    L"Materia Store",   // 200
    L"Boutique",   // 201
    L"Diner",   // 202
    L"Pharmacy",   // 203
    L"Bar",   // 204
    L"Wall Market",   // 205
    L"Corneo Hall",   // 206
    L"Corneo Hall,1f.",   // 207
    L"Corneo Hall,2f.",   // 208
    L"Torture Room",   // 209
    L"Corneo Hall,2f.",   // 210
    L"Corneo Hall,2f.",   // 211
    L"Sewer",   // 212
    L"Sewer",   // 213
    L"Honey Bee Inn",   // 214
    L"",   // 215
    L"Honey Bee Inn",   // 216
    L"",   // 217
    L"Honey Bee Inn",   // 218
    L"Honey Bee Inn",   // 219
    L"Honey Bee Inn",   // 220
    L"",   // 221
    L"Wall Market",   // 222
    L"Plate Section",   // 223
    L"Plate Section",   // 224
    L"sector 0",   // 225
    L"Outside Plates",   // 226
    L"Shinra Bldg.",   // 227
    L"Shinra Bldg.",   // 228
    L"Shinra Bldg. Stairs",   // 229
    L"Shinra Bldg. Stairs",   // 230
    L"Shinra Bldg. Stairs",   // 231
    L"Elevator",   // 232
    L"Outside Elevator",   // 233
    L"Shinra Bldg. 1f. lobby",   // 234
    L"Shinra Bldg. 2f. Lobby",   // 235
    L"Shinra Bldg. 2f. Shop",   // 236
    L"Shinra Bldg. 3f. Lobby",   // 237
    L"Shinra Bldg. 59f.",   // 238
    L"Shinra Bldg. 60f.",   // 239
    L"Shinra Bldg. 60f.",   // 240
    L"Shinra Bldg. 61f.",   // 241
    L"Shinra Bldg. 62f.",   // 242
    L"Shinra Bldg. 62f.",   // 243
    L"",   // 244
    L"Shinra Bldg. 63f.",   // 245
    L"Shinra Bldg. 63f.",   // 246
    L"Shinra Bldg. 64f.",   // 247
    L"Shinra Bldg. 65f.",   // 248
    L"Shinra Bldg. 65f.",   // 249
    L"Shinra Bldg.66f.",   // 250
    L"Shinra Bldg.66f.",   // 251
    L"Shinra Bldg.66f.",   // 252
    L"Shinra Bldg.66f.",   // 253
    L"Shinra Bldg.66f.",   // 254
    L"Conference Room",   // 255
    L"Shinra Bldg.67f.",   // 256
    L"Shinra Bldg.67f.",   // 257
    L"Shinra Bldg.67f.",   // 258
    L"Shinra Bldg.67f.",   // 259
    L"Shinra Bldg.67f.",   // 260
    L"",   // 261
    L"Shinra Bldg.68f.",   // 262
    L"Shinra Bldg.68f.",   // 263
    L"Shinra Bldg. 69f.",   // 264
    L"",   // 265
    L"Shinra Bldg. 70f.",   // 266
    L"Shinra Bldg. 70f.",   // 267
    L"Shinra Bldg. 70f.",   // 268
    L"Shinra Building 70f",   // 269
    L"Nibelheim Item Store",   // 270
    L"Nibelheim House",   // 271
    L"",   // 272
    L"Nibelheim Inn",   // 273
    L"",   // 274
    L"",   // 275
    L"'s House",   // 276
    L"",   // 277
    L"",   // 278
    L"",   // 279
    L"",   // 280
    L"",   // 281
    L"Nibelheim",   // 282
    L"",   // 283
    L"Nibelheim",   // 284
    L"",   // 285
    L"'s House",   // 286
    L"'s House",   // 287
    L"'s House",   // 288
    L"'s House",   // 289
    L"Nibelheim",   // 290
    L"Nibelheim",   // 291
    L"Nibelheim",   // 292
    L"Nibelheim",   // 293
    L"7th Heaven",   // 294
    L"",   // 295
    L"Nibelheim",   // 296
    L"Mansion1f.",   // 297
    L"Mansion1f.",   // 298
    L"Mansion2f.",   // 299
    L"Mansion2f.",   // 300
    L"MansionHidden Steps",   // 301
    L"MansionBasement",   // 302
    L"MansionBasement",   // 303
    L"MansionBasement",   // 304
    L"MansionBasement",   // 305
    L"",   // 306
    L"MansionBasement",   // 307
    L"MansionBasement",   // 308
    L"MansionBasement",   // 309
    L"MansionBasement",   // 310
    L"Mt. Nibel",   // 311
    L"Mt. Nibel",   // 312
    L"Mt. Nibel",   // 313
    L"Mt. Nibel",   // 314
    L"Nibel Reactor",   // 315
    L"Nibel Reactor",   // 316
    L"Mt. Nibel",   // 317
    L"Mt. Nibel Cave",   // 318
    L"Mt. Nibel Cave",   // 319
    L"Mt. Nibel Cave",   // 320
    L"Mt. Nibel Cave",   // 321
    L"Nibel Reactor(Int.)",   // 322
    L"Nibel Reactor(Int.)",   // 323
    L"Nibel Reactor(Int.)",   // 324
    L"",   // 325
    L"Nibel Reactor(Int.)",   // 326
    L"Nibel Reactor(Int.)",   // 327
    L"Weapon Store",   // 328
    L"Item Store",   // 329
    L"Bar",   // 330
    L"Inn: 1f",   // 331
    L"Inn: 2f",   // 332
    L"House: 1f",   // 333
    L"House: 2f",   // 334
    L"Kalm",   // 335
    L"House: 1f",   // 336
    L"House: 2f",   // 337
    L"House: 1f",   // 338
    L"House: 2f",   // 339
    L"Rear Tower (Pagoda)",   // 340
    L"House: 1f",   // 341
    L"House: 2f",   // 342
    L"Chocobo farm",   // 343
    L"Chocobo farm",   // 344
    L"Chocobo Ranch",   // 345
    L"",   // 346
    L"",   // 347
    L"Marshes",   // 348
    L"Mythril Mine",   // 349
    L"Mythril Mine",   // 350
    L"Mythril Mine",   // 351
    L"Mythril Mine",   // 352
    L"Base of Fort Condor",   // 353
    L"Entrance to Fort Condor",   // 354
    L"Fort Condor",   // 355
    L"Watch Room",   // 356
    L"",   // 357
    L"top of the mountain",   // 358
    L"Upper Junon",   // 359
    L"Upper Junon",   // 360
    L"Upper Junon",   // 361
    L"Upper Junon",   // 362
    L"Upper Junon",   // 363
    L"Weapon Store",   // 364
    L"Item Store",   // 365
    L"Materia Store",   // 366
    L"Barracks",   // 367
    L"Barracks",   // 368
    L"Barracks",   // 369
    L"Lower Junon",   // 370
    L"Lower Junon",   // 371
    L"Lower Junon",   // 372
    L"Weapon Store",   // 373
    L"Item Store",   // 374
    L"Materia Store",   // 375
    L"Junon Inn",   // 376
    L"Shinra Member's Bar",   // 377
    L"Respectable Inn",   // 378
    L"Bar",   // 379
    L"Barracks",   // 380
    L"Barracks",   // 381
    L"Junon Dock",   // 382
    L"Junon Dock",   // 383
    L"Airport",   // 384
    L"Airport",   // 385
    L"Junon Airport Path",   // 386
    L"Locker Room",   // 387
    L"Elevator",   // 388
    L"Path 2",   // 389
    L"Junon Path",   // 390
    L"Elevator",   // 391
    L"Junon Path",   // 392
    L"Junon Path",   // 393
    L"Junon Path",   // 394
    L"Elevator",   // 395
    L"Junon Branch1f.",   // 396
    L"Junon Branch2f.",   // 397
    L"Office",   // 398
    L"Office",   // 399
    L"Dr.'s Office",   // 400
    L"Press Room",   // 401
    L"Gas Room",   // 402
    L"",   // 403
    L"Submarine Dock",   // 404
    L"",   // 405
    L"Submarine Bridge",   // 406
    L"Inside Submarine",   // 407
    L"Inside Submarine",   // 408
    L"Inside Submarine",   // 409
    L"",   // 410
    L"Aljunon",   // 411
    L"Aljunon",   // 412
    L"Canon",   // 413
    L"Junon branch,(ext.)",   // 414
    L"Canon",   // 415
    L"Canon",   // 416
    L"Underwater Reactor",   // 417
    L"Underwater Reactor",   // 418
    L"Underwater Reactor",   // 419
    L"Underwater Reactor",   // 420
    L"Underwater Reactor",   // 421
    L"Underwater Reactor",   // 422
    L"Underwater Reactor",   // 423
    L"Underwater Reactor",   // 424
    L"Underwater Reactor",   // 425
    L"Underwater Reactor",   // 426
    L"Underwater Reactor",   // 427
    L"Under Junon",   // 428
    L"Dolphin Offing",   // 429
    L"",   // 430
    L"Priscilla's House",   // 431
    L"Weapon Store",   // 432
    L"Under Junon",   // 433
    L"Dolphin Offing",   // 434
    L"",   // 435
    L"Cargo Ship",   // 436
    L"Cargo Ship",   // 437
    L"",   // 438
    L"Cargo Ship",   // 439
    L"Cargo Ship",   // 440
    L"Costa del Sol Harbor",   // 441
    L"",   // 442
    L"Costa del Sol",   // 443
    L"Costa del Sol Inn",   // 444
    L"Bar",   // 445
    L"'s Villa",   // 446
    L"Cellar",   // 447
    L"Johnny's New Home",   // 448
    L"Costa del Sol",   // 449
    L"North Corel",   // 450
    L"North Corel",   // 451
    L"North Corel",   // 452
    L"North Corel",   // 453
    L"North Corel",   // 454
    L"North Corel",   // 455
    L"North Corel Inn",   // 456
    L"Ropeway Station",   // 457
    L"Mt. Corel",   // 458
    L"Mt. Corel",   // 459
    L"Corel Reactor",   // 460
    L"Mt. Corel",   // 461
    L"Mt. Corel",   // 462
    L"Mt. Corel",   // 463
    L"Mt. Corel",   // 464
    L"Mt. Corel",   // 465
    L"\"How cute!!\"",   // 466
    L"Mt. Corel",   // 467
    L"",   // 468
    L"",   // 469
    L"",   // 470
    L"Corel Prison",   // 471
    L"Basement",   // 472
    L"Corel Prison",   // 473
    L"Prison Pub",   // 474
    L"Mayor's Old House",   // 475
    L"",   // 476
    L"Container",   // 477
    L"Corel Prison",   // 478
    L"Corel Prison",   // 479
    L"",   // 480
    L"",   // 481
    L"Corel Desert",   // 482
    L"",   // 483
    L"Event square",   // 484
    L"",   // 485
    L"Speed square",   // 486
    L"Platform",   // 487
    L"Round Square",   // 488
    L"Inside the Ferris Wheel",   // 489
    L"Inside the Ferris Wheel",   // 490
    L"Ghost Hotel",   // 491
    L"Hotel Lobby",   // 492
    L"Hotel Lobby",   // 493
    L"Hotel",   // 494
    L"Hotel Shop",   // 495
    L"Ropeway Station",   // 496
    L"Terminal Floor",   // 497
    L"",   // 498
    L"Battle Square",   // 499
    L"Arena Lobby",   // 500
    L"Arena Lobby",   // 501
    L"Arena",   // 502
    L"Dio's Museum",   // 503
    L"",   // 504
    L"Wonder Square",   // 505
    L"Building 1f.",   // 506
    L"Building 2f.",   // 507
    L"",   // 508
    L"Chocobo Square",   // 509
    L"Chocobo Square",   // 510
    L"Ticket Office",   // 511
    L"Waiting Room",   // 512
    L"",   // 513
    L"Jungle",   // 514
    L"Jungle",   // 515
    L"Meltdown Reactor",   // 516
    L"Meltdown Reactor",   // 517
    L"Gongaga Village",   // 518
    L"Weapons Store",   // 519
    L"Weapons Store",   // 520
    L"Item Store",   // 521
    L"Inn",   // 522
    L"Inn",   // 523
    L"Mayor's Home",   // 524
    L"Cosmo Canyon",   // 525
    L"Cosmo Candle",   // 526
    L"Cosmo Canyon",   // 527
    L"",   // 528
    L"Cosmo Canyon",   // 529
    L"Elder's Room",   // 530
    L"Gate of Naught",   // 531
    L"Pub \"Starlet\"",   // 532
    L"Cosmo Canyon",   // 533
    L"Sealed Cave",   // 534
    L"Materia Shop",   // 535
    L"Cosmo Canyon",   // 536
    L"Nanaki's Room",   // 537
    L"Shildra Inn",   // 538
    L"Item Store",   // 539
    L"Observatory",   // 540
    L"Observatory",   // 541
    L"Observatory",   // 542
    L"Observatory",   // 543
    L"Bugen Research Center",   // 544
    L"",   // 545
    L"Cave of the Gi",   // 546
    L"Cave of the Gi",   // 547
    L"Cave of the Gi",   // 548
    L"Cave of the Gi",   // 549
    L"Cet Wall",   // 550
    L"Rocket Town",   // 551
    L"",   // 552
    L"Weapons Store",   // 553
    L"Item Store",   // 554
    L"Shanghai Inn",   // 555
    L"Shanghai Inn",   // 556
    L"Rocket Town",   // 557
    L"'s House",   // 558
    L"House",   // 559
    L"House",   // 560
    L"Rocket Launching Pad",   // 561
    L"Rocket Launching Pad",   // 562
    L"Duct",   // 563
    L"Ship Hallway",   // 564
    L"Ship Hallway",   // 565
    L"Materia Room",   // 566
    L"Cockpit",   // 567
    L"Engine Room",   // 568
    L"Escape Pod",   // 569
    L"Duct",   // 570
    L"",   // 571
    L"Wilderness",   // 572
    L"Plains",   // 573
    L"Wilderness",   // 574
    L"",   // 575
    L"Item Store",   // 576
    L"WutaiCat's House",   // 577
    L"WutaiOld Man's House",   // 578
    L"Wutai",   // 579
    L"Bar [Turtle Paradise]",   // 580
    L"'s House",   // 581
    L"'s House",   // 582
    L"Hidden Passage",   // 583
    L"Hidden Passage",   // 584
    L"Hidden Passage",   // 585
    L"WutaiGodo's Pagoda",   // 586
    L"WutaiPagoda",   // 587
    L"WutaiMain Mtn.",   // 588
    L"WutaiMain Mtn.",   // 589
    L"WutaiMain Mtn.",   // 590
    L"Hidden Room",   // 591
    L"WutaiDa-chao Statue",   // 592
    L"WutaiDa-chao Statue",   // 593
    L"WutaiDa-chao Statue",   // 594
    L"WutaiDa-chao Statue",   // 595
    L"WutaiDa-chao Statue",   // 596
    L"WutaiDa-chao Statue",   // 597
    L"WutaiDa-chao Statue",   // 598
    L"WutaiDa-chao Statue",   // 599
    L"Temple of the Ancients",   // 600
    L"Temple of the Ancients",   // 601
    L"Temple of the Ancients",   // 602
    L"Temple of the Ancients",   // 603
    L"Temple of the Ancients",   // 604
    L"Temple of the Ancients",   // 605
    L"Temple of the Ancients",   // 606
    L"Temple of the Ancients",   // 607
    L"Temple of the Ancients",   // 608
    L"Temple of the Ancients",   // 609
    L"Temple of the Ancients",   // 610
    L"Temple of the Ancients",   // 611
    L"Temple of the Ancients",   // 612
    L"",   // 613
    L"Temple of the Ancients",   // 614
    L"Temple of the Ancients",   // 615
    L"Temple of the Ancients",   // 616
    L"Bone Village",   // 617
    L"Sleeping Forest",   // 618
    L"Sleeping Forest",   // 619
    L"Ancient Forest",   // 620
    L"Ancient Forest",   // 621
    L"Ancient Forest",   // 622
    L"Ancient Forest",   // 623
    L"Ancient Forest",   // 624
    L"Corel Valley",   // 625
    L"Corel Valley",   // 626
    L"Forgotten City",   // 627
    L"Corel Valley Cave",   // 628
    L"Corel Valley Cave",   // 629
    L"Forgotten Capital",   // 630
    L"",   // 631
    L"Forgotten Capital",   // 632
    L"Forgotten Capital",   // 633
    L"Forgotten Capital",   // 634
    L"Forgotten Capital",   // 635
    L"Forgotten Capital",   // 636
    L"Forgotten City",   // 637
    L"Forgotten City",   // 638
    L"",   // 639
    L"Forgotten City",   // 640
    L"Forgotten City",   // 641
    L"",   // 642
    L"",   // 643
    L"",   // 644
    L"Forgotten City",   // 645
    L"Forgotten City",   // 646
    L"Water Altar",   // 647
    L"",   // 648
    L"Water Altar",   // 649
    L"Weapon Store",   // 650
    L"Icicle Inn",   // 651
    L"Icicle Inn",   // 652
    L"Icicle Inn Bar",   // 653
    L"Icicle Inn",   // 654
    L"Icicle Inn",   // 655
    L"Icicle Inn",   // 656
    L"Gast's House",   // 657
    L"Great Glacier",   // 658
    L"Great Glacier",   // 659
    L"Great Glacier",   // 660
    L"Frostbite Cave",   // 661
    L"Frostbite Cave",   // 662
    L"Great Glacier",   // 663
    L"Great Glacier",   // 664
    L"Great Glacier",   // 665
    L"Cave",   // 666
    L"Great Glacier",   // 667
    L"Great Glacier",   // 668
    L"",   // 669
    L"Great Glacier",   // 670
    L"Great Glacier",   // 671
    L"Great Glacier",   // 672
    L"Great Glacier",   // 673
    L"Great Glacier",   // 674
    L"Great Glacier",   // 675
    L"Great Glacier",   // 676
    L"Great Glacier",   // 677
    L"Cave",   // 678
    L"Great Glacier",   // 679
    L"Great Glacier",   // 680
    L"Great Glacier",   // 681
    L"Cave",   // 682
    L"Great Glacier",   // 683
    L"Cave",   // 684
    L"",   // 685
    L"Base of Gaea's Cliff",   // 686
    L"Base of Gaea's Cliff",   // 687
    L"Base of Gaea's Cliff",   // 688
    L"Gaea's Cliff",   // 689
    L"Inside of Gaea's Cliff",   // 690
    L"Inside of Gaea's Cliff",   // 691
    L"Gaea's Cliff",   // 692
    L"Inside of Gaea's Cliff",   // 693
    L"Gaea's Cliff",   // 694
    L"Gaea's Cliff",   // 695
    L"Inside of Gaea's Cliff",   // 696
    L"Inside of Gaea's Cliff",   // 697
    L"Inside of Gaea's Cliff",   // 698
    L"Inside of Gaea's Cliff",   // 699
    L"Crater",   // 700
    L"Crater",   // 701
    L"Whirlwind Maze",   // 702
    L"Whirlwind Maze",   // 703
    L"Whirlwind Maze",   // 704
    L"Whirlwind Maze",   // 705
    L"Inside Northern Cave",   // 706
    L"Great Cave",   // 707
    L"Great Cave",   // 708
    L"Whirlwind Maze",   // 709
    L"Whirlwind Maze",   // 710
    L"Whirlwind Maze",   // 711
    L"Mideel",   // 712
    L"Mideel",   // 713
    L"Mideel",   // 714
    L"Mideel",   // 715
    L"",   // 716
    L"Mideel,Weapon Store",   // 717
    L"Mideel,Item Store",   // 718
    L"Mideel,Materia Store",   // 719
    L"Mideel,Clinic",   // 720
    L"Mideel,House1",   // 721
    L"Mideel,House2",   // 722
    L"akao! , # 28Bdw!      H",   // 723
    L"akao! , # 28Bdw!      H",   // 724
    L"",   // 725
    L"",   // 726
    L"\"A promise under a star",   // 727
    L"Coal Train",   // 728
    L"Coal Train",   // 729
    L"Coal Train",   // 730
    L"8th Street",   // 731
    L"MidgarSector 8",   // 732
    L"Sector 8Underground",   // 733
    L"Sector 8Underground",   // 734
    L"Sector 8Underground",   // 735
    L"Winding Tunnel",   // 736
    L"Winding Tunnel",   // 737
    L"MidgarSector 8",   // 738
    L"MidgarSector 8",   // 739
    L"Mako Cannon",   // 740
    L"Mako Cannon",   // 741
    L"",   // 742
    L"",   // 743
    L"Highwindon deck",   // 744
    L"Northern Cave Crater",   // 745
    L"Northern Cave",   // 746
    L"Inside Northern Cave",   // 747
    L"Inside Northern Cave",   // 748
    L"Inside Northern Cave",   // 749
    L"Inside Northern Cave",   // 750
    L"Inside Northern Cave",   // 751
    L"Inside Northern Cave",   // 752
    L"Inside Northern Cave",   // 753
    L"Inside Northern Cave",   // 754
    L"Inside Northern Cave",   // 755
    L"Inside Northern Cave",   // 756
    L"Inside Northern Cave",   // 757
    L"Inside Northern Cave",   // 758
    L"Inside Northern Cave",   // 759
    L"Inside Northern Cave",   // 760
    L"Inside Northern Cave",   // 761
    L"Inside Northern Cave",   // 762
    L"Bottom of Northern Cave",   // 763
    L"Bottom of Northern Cave",   // 764
    L"Inside the Planet",   // 765
    L"Inside the Planet",   // 766
    L"",   // 767
    L"????",   // 768
    L"",   // 769
    L"",   // 770
    L"",   // 771
    L"Bone Village",   // 772
    L"",   // 773
    L"",   // 774
    L"Temple of the Ancients",   // 775
    L"",   // 776
    L"",   // 777
    L"Winding Tunnel",   // 778
    L"",   // 779
    L"",   // 780
    L"",   // 781
    L"",   // 782
    L"",   // 783
    L"",   // 784
    L"",   // 785
    L"",   // 786
    L"",   // 787
};

// The harvested caption for a field id, or nullptr when none exists.
inline const wchar_t* Get(int field_id)
{
    if (field_id < 0 || field_id >= kCount || !kCaptions[field_id][0])
        return nullptr;
    return kCaptions[field_id];
}

} // namespace FF7FieldCaptions
