﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using NSubstitute;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class MetadataRefreshSchedulerTests
    {
        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_ReturnsHalfRemaining()
        {
            var validUntil = DateTime.UtcNow.AddHours(2);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            subject.Should().BeCloseTo(new TimeSpan(1, 0, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_RespectsMinInterval()
        {
            var validUntil = DateTime.UtcNow.AddSeconds(10);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            subject.Should().BeCloseTo(new TimeSpan(0, 1, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_RespectsMaxInterval()
        {
            var validUntil = new DateTime(2100, 01, 01);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            var maxDelay = new TimeSpan(0, 0, 0, 0, int.MaxValue);

            subject.Should().BeCloseTo(maxDelay);
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataValidUntil_DefaultValue()
        {
            var metadata = Substitute.For<ICachedMetadata>();

            var subject = metadata.CalculateMetadataValidUntil();

            subject.Should().BeCloseTo(DateTime.UtcNow.AddHours(1));
        }
    }
}
